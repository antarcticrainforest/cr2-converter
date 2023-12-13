"""Scrtip that uploads photos to google photos."""

import argparse
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path
import readline
import signal
from socket import gethostname
import subprocess
import sys
from tempfile import NamedTemporaryFile
import time
from types import FrameType
from typing import Dict, Iterable, Iterator, List, Optional, Tuple, Union, cast
from typing_extensions import TypedDict

import appdirs
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import piexif
import sqlite3
import requests
import tomlkit
from tqdm import tqdm

APP = "photo-uploader"
lock_file = Path(f"/tmp/{APP}.lock")

logging.basicConfig(
    format="%(name)s - %(levelname)s - %(message)s", level=logging.ERROR
)
logger = logging.getLogger(APP)


DbType = TypedDict(
    "DbType",
    {
        "mdate": datetime,
        "conversion_timestamp": Optional[datetime],
        "uploaded": bool,
    },
)

ConfigText: str = """[Directories]
# This is the general configuration part, you can set the paths of the
# CR2 files that are converted to JPG as well as the paths where the JPG
# are stored

# Set the location of the CR2 files
CR2 = ""

# Set the directory where the converted JPG files should be saved to
JPG = ""

"""


def complete(text: str, state: int) -> Optional[str]:
    """Auto-completes directory names for input using tab.

    Parameters
    -----------
    - text (str):
        The current input text.
    - state (int):
        The state number for completion.

    Returns:
    - str or None: The next possible completion for the input text.
    """
    files: List[Optional[str]] = [
        f.name for f in Path().iterdir() if f.is_dir()
    ]
    return (files + [None])[state]


def input_path(prompt: str = "Enter directory path: ") -> str:
    """Prompts the user to input a directory path with tab completion support.

    Parameters
    ----------
    - prompt (str, optional):
        The prompt message for the user. Defaults to 'Enter directory path: '.

    Returns
    -------
    - str: The directory path entered by the user.
    """
    readline.set_completer_delims(" \t\n;")
    readline.parse_and_bind("tab: complete")
    readline.set_completer(complete)
    user_input = input(f"{prompt} ")
    return user_input


class PhotoUploader:
    """A class that interacts with the google photo API to upload photos.

    Parameters
    ----------

    photo_path: str
        Path(s) to the photo file(s) you want to upload.
    config: Path, default: .google-oauth.json
        Path to the service account credentials JSON file.
    album: str, default: Canon
        ID of the Google Photos album where you want to upload the photo.
    init: bool, default: False
        Initialise the google oauth procedure only.
    port: int, default 8080
        Set the port the oauth initialisation should be running
    """

    user_data_dir: Path = Path(appdirs.user_data_dir("photo-uploader"))
    user_config_dir: Path = Path(appdirs.user_config_dir("photo-uploader"))

    def __init__(
        self,
        config: Optional[Path] = None,
        album: str = "Canon",
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        steps: List[str] = ["convert", "upload"],
        override: bool = False,
    ) -> None:
        self._config_path = config or self.user_config_dir / "google_auth.json"
        credentials = json.loads(config.read_text()).get("installed", {})
        self.client_id: str = credentials.get("client_id", "")
        self.client_secret: str = credentials.get("client_secret")
        self.album = album
        self._reload = True
        self.start = start
        self.end = end
        self.start = start
        self.end = end
        self.steps = steps
        self.override = override
        self._db: Dict[str, DbType] = {}
        self.photo_upload_token = self._photo_upload_token_file.read_text()
        self._token = ""
        self.token_expiry = datetime.utcnow() - timedelta(minutes=10)
        self._create_database()

    def __iter__(
        self, inp_files: Optional[Iterable[Path]] = None
    ) -> Iterator[Tuple[Path, List[str]]]:
        self._reload = True
        try:
            inp_files = inp_files or Path(
                self.user_config["CR2"]
            ).expanduser().rglob("*.CR2")
        except FileNotFoundError:
            inp_files = []
        for file in sorted(inp_files):
            c_time = datetime.fromtimestamp(file.stat().st_ctime)
            if self.start and c_time < self.start and not self.override:
                continue
            if self.end and c_time > self.end and not self.override:
                continue
            try:
                work_done = self.database.get(file.name, {})
            except Exception as error:
                logger.error(error)
                continue
            if not work_done or self.override:
                yield file, self.steps
            else:
                try:
                    jpg_file, _ = self.jpg_from_raw(
                        file, datetime.fromisoformat(work_done["mdate"])
                    )
                except Exception as error:
                    logger.error(error)
                    continue
                if not jpg_file.is_file():
                    yield file, self.steps
                elif (
                    datetime.fromtimestamp(jpg_file.stat().st_mtime)
                    > datetime.fromisoformat(work_done["conversion_timestamp"])
                    or work_done["uploaded"] is False
                ):
                    if "upload" in self.steps:
                        yield file, ["upload"]

    def __len__(self) -> int:
        return len(list(self.__iter__()))

    def _add_to_database(
        self,
        input_file: Path,
        capture_time: datetime,
        jpg_file: Optional[Path] = None,
        uploaded: bool = False,
    ) -> None:
        """Function to add a filename and mdate to the database."""
        conn = sqlite3.connect(self.database_file)
        cursor = conn.cursor()
        if jpg_file:
            conversion_timestamp = datetime.fromtimestamp(
                jpg_file.stat().st_mtime
            )
        else:
            conversion_timestamp = None
        cursor.execute(
            "INSERT OR REPLACE INTO processed_files"
            " (filename, mdate, conversion_timestamp, uploaded)"
            " VALUES (?, ?, ?, ?)",
            (input_file.name, capture_time, conversion_timestamp, uploaded),
        )
        conn.commit()
        conn.close()
        self._reload = True

    def _create_album_if_not_exists(self) -> str:
        # Check if the album already exists
        url = "https://photoslibrary.googleapis.com/v1/albums"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            albums = response.json().get("albums", [])
            for album in albums:
                if album["title"] == self.album:
                    logger.info("Album already exists.")
                    return album["id"]

            # If the album doesn't exist, create it
            create_album_url = "https://photoslibrary.googleapis.com/v1/albums"
            create_album_payload = {"album": {"title": self.album}}
            create_response = requests.post(
                create_album_url, headers=headers, json=create_album_payload
            )

            if create_response.status_code == 200:
                created_album_id = create_response.json()["id"]
                logger.info('Album "%s" created successfully.', self.album)
                return created_album_id
                logger.warning(
                    "Failed to create album. Status code: %s",
                    create_response.status_code,
                )
                logger.warning(create_response.text)
                return ""
        else:
            logger.warning(
                "Failed to fetch albums. Status code: %s", response.status_code
            )
            logger.warning(response.text)
            return ""

    # Function to create SQLite database table if it doesn't exist
    def _create_database(self) -> None:
        conn = sqlite3.connect(self.database_file)
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS processed_files ("
            "filename TEXT PRIMARY KEY, "
            "mdate DATETIME, "
            "conversion_timestamp DATETIME, "
            "uploaded BOOLEAN)"
        )
        conn.commit()
        conn.close()

    def _convert_to_jpg(self, cr2_file: Path) -> None:
        command = [
            "dcraw",
            "-c",
            "-w",
            "-o",
            "1",
            "-q",
            "3",
            "-T",
            str(cr2_file),
        ]
        jpg_file, _ = self.jpg_from_raw(cr2_file)
        jpg_file.parent.mkdir(exist_ok=True, parents=True)
        convert_args = [
            "-auto-level",
            "-auto-gamma",
            "-sharpen",
            "0x1.0",
            "-contrast-stretch",
            "0.15x0.1",
            "-quality",
            "90",
            str(jpg_file),
        ]

        with NamedTemporaryFile(suffix=".tiff") as temp_file:
            with open(temp_file.name, "wb") as cache_file:
                subprocess.run(
                    command,
                    stdout=cache_file,
                    stderr=subprocess.PIPE,
                    check=True,
                )
            subprocess.run(
                ["convert", temp_file.name] + convert_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        # Copy metadata from CR2 to JPG
        exif_dict = piexif.load(str(cr2_file))
        out_dict: Dict[str, Dict[int, Union[int, str, bytes]]] = {}
        for principal_key in ("0th", "Exif", "1st"):
            out_dict[principal_key] = {}
            for key, value in list(exif_dict[principal_key].items()):
                if isinstance(value, (int, str)):
                    out_dict[principal_key][key] = value
                elif isinstance(value, bytes) and len(value) < 265:
                    out_dict[principal_key][key] = value
            exif_bytes = piexif.dump(out_dict)
            piexif.insert(exif_bytes, str(jpg_file))

    @staticmethod
    def _get_capture_time(cr2_file: Path) -> Optional[datetime]:
        tags = piexif.load(str(cr2_file))
        num = [
            n
            for n, v in piexif.TAGS["Exif"].items()
            if v["name"].lower() == "datetimeoriginal"
        ][0]
        c_date, _, c_time = tags["Exif"][num].decode().partition(" ")
        if c_date and c_time:
            return datetime.fromisoformat(
                f"{c_date.replace(':', '-')}T{c_time}"
            )
        return None

    @classmethod
    def _obtain_refresh_token(
        self, config_path: Path, token_file: Path, port: int = 8080
    ) -> None:
        """Create a new refresh token."""
        flow = InstalledAppFlow.from_client_secrets_file(
            config_path,
            scopes=["https://www.googleapis.com/auth/photoslibrary"],
        )
        credentials = flow.run_local_server(port=port)
        # Access token
        token_file.write_text(credentials.refresh_token)
        token_file.chmod(0o600)

    @property
    def _photo_upload_token_file(self) -> Path:
        token_file = self.user_data_dir / "photoupload.token"
        token_file.touch(0o600)
        return token_file

    @property
    def database(self) -> Dict[str, DbType]:
        """Read the db."""
        if not self._db or self._reload is True:
            conn = sqlite3.connect(self.database_file)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM processed_files")
            self._db = {}
            for (
                filename,
                mdate,
                conversion_timestamp,
                uploaded,
            ) in cursor.fetchall():
                self._db[filename] = {
                    "mdate": mdate,
                    "conversion_timestamp": conversion_timestamp,
                    "uploaded": bool(uploaded),
                }
        self._reload = False
        return self._db

    @property
    def database_file(self) -> Path:
        """Define the sqlite database file where processed files are stored."""
        return self.user_data_dir / "processed_files.db"

    @property
    def hostname(self) -> str:
        """Get the hostname of the current machine."""
        return gethostname()

    @property
    def token(self) -> str:
        """Get the google access token."""
        if self.token_expiry < datetime.utcnow():
            creds = Credentials(
                None,  # This should be set to None for refreshing tokens
                refresh_token=self.photo_upload_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
            creds.refresh(Request())
            self._token = creds.token
        return self._token

    @property
    def user_config(self) -> Dict[str, str]:
        """Read the general user config."""
        return cast(
            Dict[str, str],
            tomlkit.loads((self.user_config_dir / "config.toml").read_text())[
                "Directories"
            ],
        )

    def jpg_from_raw(
        self, cr2_file: Path, c_time: Optional[datetime] = None
    ) -> Tuple[Path, datetime]:
        """Construct the filename for the jpg output file."""
        if not c_time:
            c_time = self._get_capture_time(
                cr2_file
            ) or datetime.fromtimestamp(cr2_file.stat().st_ctime)
        jpg_dir = Path(self.user_config["JPG"]).expanduser()
        return (
            jpg_dir / str(c_time.year) / cr2_file.with_suffix(".jpg").name,
            c_time,
        )

    def process_file(self, input_file: Path, todo: List[str]) -> None:
        """Process the cr2 file according to things that have to be done."""
        logger.info(
            "Processing file %s using %s", input_file.name, ", ".join(todo)
        )
        try:
            jpg_file, capture_time = self.jpg_from_raw(input_file)
        except Exception as error:
            logger.error(error)
            return
        if "convert" in todo:
            logger.info("Converting %s to JPG", input_file.name)
            try:
                self._convert_to_jpg(input_file)
            except Exception as error:
                logger.error(error)
                return
        uploaded = False
        if "upload" in todo:
            logger.info("Uploading %s", jpg_file.name)
            for num in range(3):
                try:
                    uploaded = self.upload_photo(jpg_file)
                    break
                except Exception as error:
                    time.sleep(2)
                    if num == 2:
                        logger.error(error)
            if not uploaded:
                logger.warning("Could not upload %s", jpg_file.name)
        logger.info("Done, adding all to database")
        self._add_to_database(input_file, capture_time, jpg_file, uploaded)

    def upload_photo(self, photo_path: Path) -> bool:
        """Upload the photo to google."""
        credentials = Credentials(self.token)
        session = AuthorizedSession(credentials)
        album_id = self._create_album_if_not_exists()
        session.headers["Content-type"] = "application/octet-stream"
        session.headers["X-Goog-Upload-Protocol"] = "raw"
        photo_bytes = photo_path.read_bytes()
        session.headers["X-Goog-Upload-File-Name"] = photo_path.name
        upload_token = session.post(
            "https://photoslibrary.googleapis.com/v1/uploads", photo_bytes
        )

        # Read the photo file in binary mode
        if (upload_token.status_code == 200) and (upload_token.content):
            create_body = json.dumps(
                {
                    "albumId": album_id,
                    "newMediaItems": [
                        {
                            "description": f"uploaded by {self.hostname} for {APP}",
                            "simpleMediaItem": {
                                "uploadToken": upload_token.content.decode(),
                            },
                        }
                    ],
                },
                indent=4,
            )

            resp = session.post(
                "https://photoslibrary.googleapis.com/v1/mediaItems:batchCreate",
                create_body,
            ).json()

            logger.debug("Server response: %s", resp)

            if "newMediaItemResults" in resp:
                status = resp["newMediaItemResults"][0]["status"]
                if status.get("code") and (status.get("code") > 0):
                    logger.error(
                        "Could not add '%s' to library -- %s",
                        photo_path.name,
                        status["message"],
                    )
                else:
                    logger.info(
                        "Added '%s' to library and album '%s' ",
                        photo_path.name,
                        self.album,
                    )
                    return True
            else:
                logger.error(
                    "Could not add '%s' to library. Server Response -- %s",
                    photo_path.name,
                    resp,
                )
        else:
            logger.error(
                "Could not upload '%s'. Server Response - %s",
                photo_path.name,
                upload_token,
            )
        return False

    @classmethod
    def initialise(
        cls, google_credentials: Optional[Path] = None, port: int = 8080
    ) -> None:
        for path in cls.user_config_dir, cls.user_data_dir:
            path.mkdir(exist_ok=True, parents=True)
        config_file = cls.user_config_dir / "config.toml"
        if not config_file.is_file():
            config_file.write_text(ConfigText)

        config = tomlkit.loads(config_file.read_text())
        for key, value in config.get("general", {}).items():
            config["general"][key] = (
                input_path(f"Enter path to {key} directory [{value}]:")
                or value
            )
        config_file.write_text(tomlkit.dumps(config))
        if google_credentials is not None:
            token_file = cls.user_data_dir / "photoupload.token"
            (cls.user_config_dir / "google_auth.json").write_text(
                google_credentials.read_text()
            )
            (cls.user_config_dir / "google_auth.json").chmod(0o600)
            if not token_file.exists():
                cls._obtain_refresh_token(google_credentials, token_file, port)


def cli() -> None:
    """The command line interface for the photo uploader."""

    parser = argparse.ArgumentParser(
        description="Convert RAW photos taken from a SLR camera to JPG and"
        " upload the converted files to Google Photos",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to service account credentials JSON file.",
        default=PhotoUploader.user_config_dir / "google_auth.json",
    )
    parser.add_argument(
        "-s",
        "--start",
        type=lambda d: datetime.fromisoformat(d),
        help="Start date for selecting photos",
    )
    parser.add_argument(
        "-e",
        "--end",
        type=lambda d: datetime.fromisoformat(d),
        help="End date for selecting photos",
    )
    parser.add_argument(
        "-a",
        "--album",
        type=str,
        help="ID of the Google Photos album where you want to upload the photo.",
        default="Canon",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialise the google oauth procedure.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Set the port the oauth initialisation should be running",
    )
    parser.add_argument(
        "-o",
        "--override",
        "--overwrite",
        action="store_true",
        default=False,
        help="Replace existing files.",
    )
    parser.add_argument(
        "--steps",
        nargs="+",
        default=["convert", "upload"],
        choices=["convert", "upload"],
        help="Set the todo items that need to be done.",
    )
    parser.add_argument(
        "-d",
        "--daemon",
        action="store_true",
        default=False,
        help="Run in daemon mode.",
    )
    parser.add_argument(
        "-v",
        action="count",
        default=0,
        help="Increase verbosity",
    )
    args = parser.parse_args()
    logger.setLevel(max(logging.ERROR - (10 + args.v * 10), 10))
    lock_file.touch()
    if args.init is True:
        PhotoUploader.initialise(args.config, args.port)
        return
    if args.daemon is False:
        photos = PhotoUploader(
            start=args.start,
            end=args.end,
            config=args.config,
            album=args.album,
            override=args.override,
            steps=args.steps,
        )
        for path, todo in tqdm(photos, desc="Processing Photos", leave=True):
            photos.process_file(path, todo)
    else:
        photos = PhotoUploader(
            config=args.config,
            album=args.album,
            steps=args.steps,
        )
        logger.setLevel(logging.INFO)
        while True:
            for path, todo in photos:
                photos.process_file(path, todo)
            time.sleep(60)


def signal_handler(sig: int, frame: Optional[FrameType] = None) -> None:
    """Handle any kind of termination signal."""

    if lock_file.is_file():
        lock_file.unlink()
    print("Exiting")
    sys.exit(sig)


def main() -> None:
    """Wrapper for calling the cli method."""
    if lock_file.is_file():
        raise SystemExit(
            f"{lock_file} exists, another process is already running."
            " If you are sure that there is no other process running,"
            " You can delete this file."
        )
    for sig in (
        signal.SIGTERM,
        signal.SIGABRT,
        signal.SIGINT,
        signal.SIGQUIT,
    ):
        signal.signal(sig, signal_handler)
    cli()
    lock_file.unlink()


if __name__ == "__main__":
    main()
