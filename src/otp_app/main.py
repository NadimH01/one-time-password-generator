import tkinter as tk

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

    app = OTPApplication(root)
    app.set_accounts(
        [
            "alice",
            "bob",
            "demo-account",
        ]
    )

    root.mainloop()


if __name__ == "__main__":
    main()
    