"""
EXIF Metadata & Document Sanitizer
-----------------------------------
An offline desktop tool that strips hidden tracking metadata (GPS
coordinates, camera models, author names, timestamps) from images,
PDFs, and Word documents before they're shared. Everything runs
locally — no network calls, no uploads.

Run with:  python app.py
"""

import threading
import traceback
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox

from PIL import Image
from pypdf import PdfReader, PdfWriter
from docx import Document


# --------------------------------------------------------------------------
# Stripping Modules — one function per file type, each takes a source path
# and writes a cleaned copy to dst_path.
# --------------------------------------------------------------------------

def strip_image_metadata(src_path: Path, dst_path: Path) -> None:
    """Re-save an image built from raw pixel data only, which drops the
    EXIF block (GPS coordinates, camera make/model, timestamps, etc.)."""
    with Image.open(src_path) as img:
        data = list(img.getdata())
        clean_img = Image.new(img.mode, img.size)
        clean_img.putdata(data)

        save_kwargs = {}
        if img.format == "JPEG":
            save_kwargs["quality"] = 95  # avoid re-compression artifacts
        clean_img.save(dst_path, format=img.format, **save_kwargs)


def strip_pdf_metadata(src_path: Path, dst_path: Path) -> None:
    """Clone every page into a fresh PdfWriter and set an empty metadata
    dict, wiping author/producer/creation-date and any custom fields."""
    reader = PdfReader(str(src_path))
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.add_metadata({})  # replaces the whole /Info dictionary

    with open(dst_path, "wb") as f:
        writer.write(f)


def strip_docx_metadata(src_path: Path, dst_path: Path) -> None:
    """Clear python-docx's core_properties (author, last-modified-by,
    comments, title, etc.) and save a clean copy."""
    doc = Document(str(src_path))
    props = doc.core_properties

    props.author = ""
    props.last_modified_by = ""
    props.comments = ""
    props.title = ""
    props.subject = ""
    props.keywords = ""
    props.category = ""
    props.content_status = ""

    doc.save(str(dst_path))


# Extension -> handler routing table (the "Routing Engine")
HANDLERS = {
    ".jpg": strip_image_metadata,
    ".jpeg": strip_image_metadata,
    ".png": strip_image_metadata,
    ".pdf": strip_pdf_metadata,
    ".docx": strip_docx_metadata,
}


def sanitize_file(src_path: Path) -> Path:
    """Look up the right handler for this file's extension, run it, and
    return the path of the cleaned output file."""
    ext = src_path.suffix.lower()
    handler = HANDLERS.get(ext)
    if handler is None:
        raise ValueError(f"Unsupported file type: {ext}")

    out_dir = src_path.parent / "sanitized_output"
    out_dir.mkdir(exist_ok=True)
    dst_path = out_dir / f"{src_path.stem}_clean{src_path.suffix}"

    handler(src_path, dst_path)
    return dst_path


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

class SanitizerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Metadata Sanitizer")
        self.geometry("560x480")
        self.minsize(480, 420)

        self.selected_files: list[Path] = []

        self._build_widgets()

    def _build_widgets(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        header = ctk.CTkLabel(
            self, text="EXIF & Document Metadata Sanitizer",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        header.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")

        subtitle = ctk.CTkLabel(
            self,
            text="Strips GPS data, author names, and timestamps. 100% offline.",
            font=ctk.CTkFont(size=12), text_color="gray",
        )
        subtitle.grid(row=1, column=0, padx=20, pady=(0, 15), sticky="w")

        self.select_btn = ctk.CTkButton(
            self, text="Select Files", command=self.select_files
        )
        self.select_btn.grid(row=2, column=0, padx=20, pady=5, sticky="ew")

        self.file_box = ctk.CTkTextbox(self, height=200)
        self.file_box.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")
        self.file_box.configure(state="disabled")

        self.progress = ctk.CTkProgressBar(self)
        self.progress.grid(row=4, column=0, padx=20, pady=(10, 5), sticky="ew")
        self.progress.set(0)

        self.status_label = ctk.CTkLabel(self, text="Ready.", text_color="gray")
        self.status_label.grid(row=5, column=0, padx=20, pady=(0, 10), sticky="w")

        self.sanitize_btn = ctk.CTkButton(
            self, text="Sanitize Files", fg_color="#2fa572",
            hover_color="#248a5c", command=self.start_sanitize_thread,
        )
        self.sanitize_btn.grid(row=6, column=0, padx=20, pady=(0, 20), sticky="ew")

    # ---- File selection ----

    def select_files(self):
        paths = filedialog.askopenfilenames(
            title="Select files to sanitize",
            filetypes=[
                ("Supported files", "*.jpg *.jpeg *.png *.pdf *.docx"),
                ("All files", "*.*"),
            ],
        )
        if not paths:
            return

        self.selected_files = [Path(p) for p in paths]
        self._refresh_file_list()

    def _refresh_file_list(self):
        self.file_box.configure(state="normal")
        self.file_box.delete("1.0", "end")
        for p in self.selected_files:
            self.file_box.insert("end", f"{p.name}\n")
        self.file_box.configure(state="disabled")

    # ---- Sanitization (runs in a background thread) ----

    def start_sanitize_thread(self):
        if not self.selected_files:
            messagebox.showwarning("No files", "Select at least one file first.")
            return

        self.sanitize_btn.configure(state="disabled")
        self.select_btn.configure(state="disabled")
        self.progress.set(0)

        thread = threading.Thread(target=self._sanitize_worker, daemon=True)
        thread.start()

    def _sanitize_worker(self):
        total = len(self.selected_files)
        errors = []

        for i, path in enumerate(self.selected_files, start=1):
            self._set_status(f"Processing {path.name} ({i}/{total})...")
            try:
                sanitize_file(path)
            except Exception as exc:
                errors.append((path.name, str(exc)))
                traceback.print_exc()

            self._set_progress(i / total)

        if errors:
            summary = "\n".join(f"- {name}: {msg}" for name, msg in errors)
            self._set_status(f"Done with {len(errors)} error(s).")
            self.after(0, lambda: messagebox.showerror(
                "Some files failed",
                f"The following files could not be processed:\n\n{summary}",
            ))
        else:
            self._set_status(f"Done. {total} file(s) sanitized -> sanitized_output/")

        self.after(0, self._reset_buttons)

    # ---- Thread-safe UI helpers ----
    # Widgets can only be touched from the main thread, so worker calls
    # route through self.after(0, ...) to hop back onto it.

    def _set_status(self, text: str):
        self.after(0, lambda: self.status_label.configure(text=text))

    def _set_progress(self, value: float):
        self.after(0, lambda: self.progress.set(value))

    def _reset_buttons(self):
        self.sanitize_btn.configure(state="normal")
        self.select_btn.configure(state="normal")


if __name__ == "__main__":
    app = SanitizerApp()
    app.mainloop()
