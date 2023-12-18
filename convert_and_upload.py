"""Scrtip that uploads photos to google photos."""

import argparse
import base64
from datetime import datetime, timedelta
from getpass import getpass
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import readline
import signal
from socket import gethostname
import subprocess
import sys
import sqlite3
from tempfile import NamedTemporaryFile
import time
from types import FrameType
from typing import Dict, Iterator, List, Optional, Tuple, Union, cast
from typing_extensions import TypedDict

import appdirs
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from pcloud import PyCloud, api
import piexif
import requests
import tomlkit
from tqdm import tqdm

APP = "photo-uploader"
lock_file = Path(f"/tmp/{APP}.lock")

logging.basicConfig(
    format="%(name)s - %(asctime)s - %(levelname)s: %(message)s",
    level=logging.ERROR,
    datefmt="[%Y-%m-%dT%H:%M:%S]",
)
logger_format = logging.Formatter(
    "%(name)s - %(asctime)s - %(levelname)s: %(message)s",
    datefmt="[%Y-%m-%dT%H:%M:%S]",
)


logger = logging.getLogger(APP)
logging.getLogger("pcloud").setLevel(logging.WARNING)


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
# RAW files that are converted to JPG as well as the paths where the JPG
# are stored

# Set the location of the RAW files
RAW = ""

# Set the directory where the converted JPG files should be saved to
JPG = ""

[Pcloud]
# If you have a pcloud account, you can set here the backup destination
# of the RAW raw camera files.
#
# Note: The password will be stored in a separate file. In order to set or
# update you must run the `convert_and_upload` script with the --init flag.
#
#
use_pcloud = false
# Set your pcloud user name, leave blank if you don't have one or don't whish
# to backup the RAW files
username = ""

# Set the parent folder where the backup should be placed in on pcloud
folder = "/Camera"
"""

RAW_FORMATS = (
    ".3fr",
    ".ari",
    ".arw",
    ".bay",
    ".braw",
    ".crw",
    ".cr2",
    ".cr3",
    ".cap",
    ".dcs",
    ".dcr",
    ".dng",
    ".drf",
    ".eip",
    ".erf",
    ".fff",
    ".gpr",
    ".iiq",
    ".k25",
    ".kdc",
    ".mdc",
    ".mef",
    ".mos",
    ".mrw",
    ".nef",
    ".nrw",
    ".obm",
    ".orf",
    ".pef",
    ".ptx",
    ".pxn",
    ".r3d",
    ".raf",
    ".raw",
    ".rwl",
    ".rw2",
    ".rwz",
    ".sr2",
    ".srf",
    ".srw",
    ".tif",
    ".x3f",
)


def add_file_handle(log_level: int = logging.INFO) -> None:
    """Add a file log handle to the logger."""
    base_name = APP
    log_dir = Path(appdirs.user_log_dir(base_name))
    log_dir.mkdir(exist_ok=True, parents=True)
    logger_file_handle = RotatingFileHandler(
        log_dir / f"{base_name}.log",
        mode="a",
        maxBytes=5 * 1024**2,
        backupCount=5,
        encoding="utf-8",
        delay=False,
    )
    logger_file_handle.setFormatter(logger_format)
    logger_file_handle.setLevel(min(log_level, logging.INFO))
    logger.addHandler(logger_file_handle)


def rglob(input_dir: Union[Path, str]) -> Iterator[Path]:
    """Recursively find all possible raw formats."""
    input_dir = Path(input_dir).expanduser()
    if not input_dir.is_dir():
        raise FileNotFoundError("Directory does not exist.")
    for suffix in RAW_FORMATS + tuple(map(str.upper, RAW_FORMATS)):
        for file_name in input_dir.rglob(f"*{suffix}"):
            yield file_name


def get_password() -> bytes:
    """Ask the user for a password."""
    password1 = getpass("Enter your pcloud password: ")
    password2 = getpass("Re-enter your pcloud password: ")
    while password1 != password2:
        print("Passwords do not match!")
        password1 = getpass("Enter your pcloud password: ")
        password2 = getpass("Re-enter your pcloud password: ")
    return base64.b64encode(password1.encode())


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

    config: Path, default: .google-oauth.json
        Path to the service account credentials JSON file.
    album: str, default: Canon
        ID of the Google Photos album where you want to upload the photo.
    start: datetime, default: None
        Start date for selecting photos,
    end: datetime, default: None
        Start date for selecting photos,
    steps: list[str], default: convert, upload
        Set the todo items that need to be done.
    override: bool, default: False
        Replace existing files.

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
        config = config or self.user_config_dir / "google_auth.json"
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

    def __iter__(self) -> Iterator[Tuple[Path, List[str]]]:
        self._reload = True
        try:
            inp_files = rglob(self.user_config["Directories"]["RAW"])
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
                yield file, self.steps + ["copy_metadata"]
            else:
                try:
                    jpg_file, _ = self.jpg_from_raw(
                        file, datetime.fromisoformat(work_done["mdate"])
                    )
                except Exception as error:
                    logger.error(error)
                    continue
                if not jpg_file.is_file():
                    yield file, self.steps + ["copy_metadata"]
                elif (
                    datetime.fromtimestamp(jpg_file.stat().st_mtime)
                    > datetime.fromisoformat(work_done["conversion_timestamp"])
                    or work_done["uploaded"] is False
                ):
                    if "upload" in self.steps:
                        yield file, ["copy_metadata", "upload"]

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

    def _convert_to_jpg(self, raw_file: Path) -> None:
        command = [
            "dcraw",
            "-c",
            "-w",
            "-o",
            "1",
            "-q",
            "3",
            "-T",
            str(raw_file),
        ]
        jpg_file, _ = self.jpg_from_raw(raw_file)
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

    @staticmethod
    def _copy_metadata(raw_file: Path, jpg_file: Path) -> None:
        """Copy metadata from RAW to JPG."""
        exif_dict = piexif.load(str(raw_file))
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
    def _get_capture_time(raw_file: Path) -> Optional[datetime]:
        tags = piexif.load(str(raw_file))
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
    def user_config(self) -> Dict[str, Dict[str, str]]:
        """Read the general user config."""
        return cast(
            Dict[str, Dict[str, str]],
            tomlkit.loads((self.user_config_dir / "config.toml").read_text()),
        )

    def jpg_from_raw(
        self, raw_file: Path, c_time: Optional[datetime] = None
    ) -> Tuple[Path, datetime]:
        """Construct the filename for the jpg output file."""
        if not c_time:
            c_time = self._get_capture_time(
                raw_file
            ) or datetime.fromtimestamp(raw_file.stat().st_ctime)
        jpg_dir = Path(self.user_config["Directories"]["JPG"]).expanduser()
        return (
            jpg_dir / str(c_time.year) / raw_file.with_suffix(".jpg").name,
            c_time,
        )

    def process_file(self, input_file: Path, todo: List[str]) -> int:
        """Process the raw file according to things that have to be done.

        Parameters
        ----------
        input_file: Path
            The input raw file that should be processed.
        todo: list[str]
            The tasks that should be done.

        Returns
        -------
        int: 0 if now work on any file was done, 1 if work was done.
        """
        logger.info(
            "Processing file %s using %s", input_file.name, ", ".join(todo)
        )
        process_steps = 0
        try:
            jpg_file, capture_time = self.jpg_from_raw(input_file)
        except Exception as error:
            logger.error(error)
            return process_steps
        if "convert" in todo:
            logger.info("Converting %s to JPG", input_file.name)
            try:
                self._convert_to_jpg(input_file)
            except Exception as error:
                logger.error(error)
                return process_steps
            process_steps += 1
        if "copy_metadata" in todo:
            logger.info("Augmenting jpg meta data")
            try:
                self._copy_metadata(input_file, jpg_file)
                process_steps += 1
            except Exception as error:
                logger.error(error)
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
            else:
                process_steps += 1
        logger.info("Done, adding all to database")
        self._add_to_database(input_file, capture_time, jpg_file, uploaded)
        return int(process_steps > 1)

    def sync_to_pcloud(self) -> None:
        """Sync all raw photos to pcloud."""
        if not self.user_config["Pcloud"]["use_pcloud"]:
            return
        try:
            password = base64.b64decode(
                (self.user_data_dir / "passwd.pcloud").read_bytes()
            ).decode()
        except FileNotFoundError:
            logger.critical(
                "Could not read password, use %s --init", sys.argv[0]
            )
            return
        pcloud = PyCloud(
            self.user_config["Pcloud"]["username"],
            password,
            endpoint="nearest",
        )
        raw_path = Path(self.user_config["Directories"]["RAW"])
        pcloud_folder = (
            Path(self.user_config["Pcloud"]["folder"]) / raw_path.name
        )
        folderid = (
            pcloud.createfolderifnotexists(
                path=str(pcloud_folder),
                folderid=0,
            )
            .get("metadata", {})
            .get("folderid")
        )
        pcloud_files = {
            p["name"]: p
            for p in pcloud.listfolder(folderid=folderid)
            .get("metadata", {})
            .get("contents", [])
        }
        files_to_upload = [
            f
            for f in rglob(raw_path)
            if f.stat().st_size != pcloud_files.get(f.name, {}).get("size", 0)
        ]
        files_to_download = []
        for file, metadata in pcloud_files.items():
            if not (raw_path / file).is_file():
                files_to_download.append(pcloud_folder / file)
        if files_to_download:
            logger.info(
                "Downloading %i files from pcloud", len(files_to_download)
            )
        for file in tqdm(
            files_to_download, desc="Downloading files", leave=False
        ):
            fd = pcloud.file_open(path=str(file), flags=api.O_CREAT).get("fd")
            try:
                count = pcloud.file_size(fd=fd).get("size")
                (raw_path / file.name).write_bytes(
                    pcloud.file_read(fd=fd, count=count)
                )
            finally:
                pcloud.file_close(fd=fd)
        if files_to_upload:
            logger.info("Uploading %i files to pcloud", len(files_to_download))

        for file in tqdm(files_to_upload, desc="Uploading files", leave=False):
            pcloud.uploadfile(files=[str(file)], folderid=folderid)

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
                            "description": f"uploaded {photo_path.name} by "
                            f"{self.hostname} for {APP}",
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
        """Setup the configuration of the upload script.

        This method should be applied before running the procedure for the
        first time.

        Parameters
        ----------
        google_credentials: Path, default: None
            Path to the json file holding the google oauth credentials.
        port: int, default 8080
            Set the port the oauth initialisation should be running
        """

        for path in cls.user_config_dir, cls.user_data_dir:
            path.mkdir(exist_ok=True, parents=True)
        config_file = cls.user_config_dir / "config.toml"
        if not config_file.is_file():
            config_file.write_text(ConfigText)

        config = tomlkit.loads(config_file.read_text())
        for key, value in config.get("Directories", {}).items():
            config["Directories"][key] = (
                input_path(f"Enter path to {key} directory [{value}]:")
                or value
            )
        use_pcloud = input(
            "Do you want to use pcloud for backing up your "
            "RAW photos? [y|N] "
        ).lower()
        password_file = cls.user_data_dir / "passwd.pcloud"
        if use_pcloud.startswith("y"):
            config["Pcloud"]["use_pcloud"] = True
            config["Pcloud"]["username"] = (
                input(
                    "Set pcloud username that should be used: "
                    f"[{config['Pcloud']['username']}] "
                ).strip()
                or config["Pcloud"]["username"]
            )
            password_file.write_bytes(get_password())
            password_file.chmod(0o600)
            config["Pcloud"]["folder"] = (
                input(
                    "Set the parent folder where the backup is placed to:"
                    f" [{config['Pcloud']['folder']}] "
                ).strip()
                or config["Pcloud"]["folder"]
            )
        else:
            config["Pcloud"]["use_pcloud"] = False
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
    if args.init is True:
        PhotoUploader.initialise(args.config, args.port)
        return
    lock_file.touch()
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
                _ = photos.process_file(path, todo)
            try:
                photos.sync_to_pcloud()
            except Exception as error:
                logger.error("Pcloud sync failed: %s", error)
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
    add_file_handle()
    exit_status = 0
    try:
        cli()
    except KeyboardInterrupt:
        pass
    except Exception as error:
        logger.exception(error)
        exit_status = 1
    if lock_file.is_file():
        lock_file.unlink()
    sys.exit(exit_status)


if __name__ == "__main__":
    main()
