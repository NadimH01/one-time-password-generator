import tkinter as tk
from tkinter import ttk


class OTPApplication(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=15)
        self.master = master
        self.pack(fill="both", expand=True)
        self._create_widgets()

    def _create_widgets(self):
        self._create_title()
        self._create_notebook()
        self._create_status_area()

    def _create_title(self):
        title = ttk.Label(
            self,
            text="One-Time Password Generator",
            font=("Segoe UI", 18, "bold"),
        )
        title.pack(pady=(0, 15))

    def _create_notebook(self):
        self.notebook = ttk.Notebook(self)
        self.enrolment_tab = ttk.Frame(self.notebook, padding=20)
        self.generator_tab = ttk.Frame(self.notebook, padding=20)
        self.verifier_tab = ttk.Frame(self.notebook, padding=20)

        self.notebook.add(self.enrolment_tab, text="Enrolment")
        self.notebook.add(self.generator_tab, text="Generator")
        self.notebook.add(self.verifier_tab, text="Verifier")
        self.notebook.pack(fill="both", expand=True)

        self._create_enrolment_tab()
        self._create_generator_tab()
        self._create_verifier_tab()

    def _create_enrolment_tab(self):
        heading = ttk.Label(
            self.enrolment_tab,
            text="Create Demo Account",
            font=("Segoe UI", 14, "bold"),
        )
        heading.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))

        ttk.Label(self.enrolment_tab, text="Account name:").grid(
            row=1, column=0, sticky="w", padx=(0, 10), pady=5
        )
        self.account_name_var = tk.StringVar()
        self.account_name_entry = ttk.Entry(
            self.enrolment_tab,
            textvariable=self.account_name_var,
            width=35,
        )
        self.account_name_entry.grid(row=1, column=1, sticky="ew", pady=5)

        self.create_account_button = ttk.Button(
            self.enrolment_tab,
            text="Create Account",
            command=self._on_create_account,
        )
        self.create_account_button.grid(
            row=2, column=1, sticky="e", pady=(15, 0)
        )
        self.enrolment_tab.columnconfigure(1, weight=1)

    def _on_create_account(self):
        account_name = self.account_name_var.get().strip()
        if not account_name:
            self.set_status("Enter an account name.", error=True)
            return
        self.set_status(f"Account creation requested: {account_name}")

    def _create_generator_tab(self):
        heading = ttk.Label(
            self.generator_tab,
            text="Generate TOTP",
            font=("Segoe UI", 14, "bold"),
        )
        heading.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))

        ttk.Label(self.generator_tab, text="Account:").grid(
            row=1, column=0, sticky="w", padx=(0, 10), pady=5
        )
        self.generator_account_var = tk.StringVar()
        self.generator_account_combo = ttk.Combobox(
            self.generator_tab,
            textvariable=self.generator_account_var,
            state="readonly",
            width=30,
        )
        self.generator_account_combo.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Label(self.generator_tab, text="Current OTP:").grid(
            row=2, column=0, sticky="w", pady=(20, 5)
        )
        self.current_otp_var = tk.StringVar(value="------")
        self.current_otp_label = ttk.Label(
            self.generator_tab,
            textvariable=self.current_otp_var,
            font=("Consolas", 30, "bold"),
        )
        self.current_otp_label.grid(
            row=2, column=1, sticky="w", pady=(20, 5)
        )

        ttk.Label(self.generator_tab, text="Time remaining:").grid(
            row=3, column=0, sticky="w", pady=5
        )
        self.countdown_var = tk.StringVar(value="-- seconds")
        self.countdown_label = ttk.Label(
            self.generator_tab,
            textvariable=self.countdown_var,
            font=("Segoe UI", 12),
        )
        self.countdown_label.grid(row=3, column=1, sticky="w", pady=5)
        self.generator_tab.columnconfigure(1, weight=1)

    def _create_verifier_tab(self):
        heading = ttk.Label(
            self.verifier_tab,
            text="Verify TOTP",
            font=("Segoe UI", 14, "bold"),
        )
        heading.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))

        ttk.Label(self.verifier_tab, text="Account:").grid(
            row=1, column=0, sticky="w", padx=(0, 10), pady=5
        )
        self.verifier_account_var = tk.StringVar()
        self.verifier_account_combo = ttk.Combobox(
            self.verifier_tab,
            textvariable=self.verifier_account_var,
            state="readonly",
            width=30,
        )
        self.verifier_account_combo.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Label(self.verifier_tab, text="OTP:").grid(
            row=2, column=0, sticky="w", padx=(0, 10), pady=5
        )
        self.otp_input_var = tk.StringVar()
        self.otp_entry = ttk.Entry(
            self.verifier_tab,
            textvariable=self.otp_input_var,
            width=20,
        )
        self.otp_entry.grid(row=2, column=1, sticky="w", pady=5)

        self.verify_button = ttk.Button(
            self.verifier_tab,
            text="Verify",
            command=self._on_verify,
        )
        self.verify_button.grid(row=3, column=1, sticky="w", pady=(15, 5))

        ttk.Label(self.verifier_tab, text="Result:").grid(
            row=4, column=0, sticky="w", pady=(15, 5)
        )
        self.verification_result_var = tk.StringVar(
            value="No verification performed."
        )
        self.verification_result_label = ttk.Label(
            self.verifier_tab,
            textvariable=self.verification_result_var,
        )
        self.verification_result_label.grid(
            row=4, column=1, sticky="w", pady=(15, 5)
        )
        self.verifier_tab.columnconfigure(1, weight=1)

    def _on_verify(self):
        account = self.verifier_account_var.get()
        otp = self.otp_input_var.get()
        if not account:
            self.set_status("Select an account.", error=True)
            return
        if not otp:
            self.set_status("Enter an OTP.", error=True)
            return

        self.verification_result_var.set("Verification requested.")
        self.set_status("Verification request received.")

    def _create_status_area(self):
        separator = ttk.Separator(self, orient="horizontal")
        separator.pack(fill="x", pady=(15, 10))
        self.status_var = tk.StringVar(value="Ready.")
        self.status_label = ttk.Label(self, textvariable=self.status_var)
        self.status_label.pack(anchor="w")

    def set_status(self, message: str, error: bool = False):
        self.status_var.set(message)
        self.status_label.configure(foreground="red" if error else "")

    def set_accounts(self, account_names):
        names = list(account_names)
        self.generator_account_combo["values"] = names
        self.verifier_account_combo["values"] = names

        if names:
            if self.generator_account_var.get() not in names:
                self.generator_account_var.set(names[0])
            if self.verifier_account_var.get() not in names:
                self.verifier_account_var.set(names[0])
