import tkinter as tk
from tkinter import messagebox

from .app_storage import (
    initialise_application_storage,
)
from .gui import OTPApplication


def main():

    root = tk.Tk()

    root.title(
        "One-Time Password Generator"
    )

    root.geometry(
        "650x450"
    )

    root.minsize(
        600,
        400,
    )

    try:
        storage = initialise_application_storage()
    except Exception as exc:
        messagebox.showerror(
            "Storage Error",
            str(exc),
        )
        root.destroy()
        return

    OTPApplication(
        root,
        storage.connection,
        storage.storage_key,
    )

    root.mainloop()
    storage.connection.close()


if __name__ == "__main__":
    main()
    