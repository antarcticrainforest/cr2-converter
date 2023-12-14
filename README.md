# cr2 Converter
A Python script to convert RAW photos taken from an SLR camera to JPG and upload the converted files to Google Photos.

## Installation

Clone the repository:

```console
git clone https://github.com/yourusername/photo-uploader.git
```

Install required dependencies:

```console
python3 -m pip install -r requirements.txt
```

## Google Cloud App Setup

To use this script, you'll need to retrieve OAuth credentials and configure the destination directories for CR2 and JPG files.
Obtaining OAuth Credentials

1.    Go to the Google Developers Console.
2.    Create a new project or select an existing one.
3.    Go to the "APIs & Services" > "Credentials" section.
4.    Create credentials (OAuth client ID).
5.    Download the JSON file containing your OAuth client ID and secret.
6.    Save the downloaded JSON file as oauth.json.


## Initialization Process

After retrieving the oauth.json credentials file:

Run the script with the --init option:

```console
python3 convert_and_upload.py --init
```

Follow the prompted instructions to authorize the application and generate tokens.
After completion, the configuration will
be saved in ~/.config/photo-uploader/config.toml.

## Usage

Run the script using the command:

```console
python convert_and_upload.py [arguments]
```

For help on available arguments, use:

```console
python convert_and_upload.py --help
```

```bash
Arguments

    -s, --start: Start date for selecting photos (default: None)
    -e, --end: End date for selecting photos (default: None)
    -a, --album: ID of the Google Photos album where you want to upload the photo. (default: Canon)
    -o, --override, --overwrite: Replace existing files. (default: False)
    --steps: Set the todo items that need to be done. (default: ['convert', 'upload'])
    -d, --daemon: Run in daemon mode. (default: False)
    -v: Increase verbosity (default: 0)
```
For advanced configurations, edit ~/.config/photo-uploader/config.toml:

```toml
[Directories]
# This is the general configuration part, you can set the paths of the
# CR2 files that are converted to JPG as well as the paths where the JPG
# are stored

# Set the location of the CR2 files
CR2 = ""

# Set the directory where the converted JPG files should be saved to
JPG = ""

[Pcloud]
# If you have a pcloud account, you can set here the backup destination
# of the CR2 raw camera files.
# Note: The password will be stored in a separate file. In order to set or
# update you must run the `convert_and_upload` script with the --init flag.
#
use_pcloud = true
# Set your pcloud user name, leave blank if you don't have one or don't whish
# to backup the CR2 files
username = ""

# Set the parent folder where the backup should be placed in on pcloud
folder = ""
```
## Daemon Mode

The daemon mode of the script enables continuous monitoring for new incoming
files in a specified directory. It automatically converts and uploads these
files to Google Photos.

## pCloud Sync Feature

The script includes a feature to sync raw photos (.cr2 files) to a pCloud account.
The script will only sync file with your pcloud account if run in daemon:

```console
python3 convert_and_upload.py --daemon
```
The script will sync the raw photos (files with the .cr2 extension) to your
pCloud storage using the provided pCloud account details.

Make sure to set up the pCloud configuration properly using the --init flag
before using the pCloud sync feature.
Ensure that the `config.toml` file contains accurate pCloud account details
for successful syncing.


### Usage with Systemd

To run the script in daemon mode using systemd:

1. Create a systemd service file, e.g., `photo-converter.service`,
with the following contents:

```plaintext
   [Unit]
   Description=Photo Uploader Daemon
   After=network.target

   [Service]
   Type=simple
   ExecStart=/usr/bin/python3 /path/to/convert_and_upload.py -d
   WorkingDirectory=/path/to/your/script/directory
   Restart=always

   [Install]
   WantedBy=multi-user.target
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.
