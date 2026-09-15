# Metadata Sanitizer

A local, offline desktop tool that strips hidden tracking metadata from
files before you share them — GPS coordinates and camera info from
photos, author names and edit history from Word docs, and the info
dictionary from PDFs. Nothing leaves your machine.

## What it strips

| File type   | Library      | Removed                                              |
|-------------|--------------|-------------------------------------------------------|
| `.jpg/.jpeg/.png` | Pillow  | EXIF (GPS coords, camera make/model, timestamps)      |
| `.pdf`      | pypdf        | Author, producer, creation/mod dates, custom fields    |
| `.docx`     | python-docx  | Author, last-modified-by, comments, title, subject     |

## Requirements

- Python 3.10+

## Install

```bash
cd metadata_sanitizer
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

1. Click **Select Files** and choose one or more `.jpg`, `.png`, `.pdf`,
   or `.docx` files.
2. Click **Sanitize Files**.
3. Cleaned copies are written to a `sanitized_output/` folder next to
   the originals, named `<original>_clean.<ext>`.

Originals are never modified or deleted.

## Project structure

```
metadata_sanitizer/
├── app.py              # CustomTkinter GUI + routing engine + stripping logic
├── requirements.txt    # customtkinter, pillow, pypdf, python-docx
└── test_files/          # Drop sample files here to test with
```

## How it works

- **Routing engine** — `sanitize_file()` looks at the file extension and
  dispatches to the matching handler in `HANDLERS`.
- **Images** — reconstructed from raw pixel data only, so no EXIF block
  survives the save.
- **PDFs** — pages are cloned into a fresh `PdfWriter`, then
  `add_metadata({})` replaces the entire `/Info` dictionary.
- **DOCX** — `core_properties` fields are overwritten with empty strings.
- Processing runs on a background thread so the UI stays responsive;
  a progress bar and status label track each file.

## Notes

- Unsupported file types are skipped with an error listed at the end of
  the run — other files in the batch still process normally.
- Re-saved JPEGs use quality 95 to minimize recompression loss.
