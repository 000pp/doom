from textual.app import ComposeResult
from textual.widgets import Footer, Input, Label, Button
from textual.containers import Horizontal, Vertical, Center
from textual.screen import Screen

from .loading_screen import LoadingScreen

class LoginScreen(Screen):
    DEFAULT_CSS = """
    LoginScreen {
        background: #1e1e2e;
        align: center middle;
    }

    LoginScreen .login-container {
        width: 50%;
        height: auto;
    }

    LoginScreen #login-title {
        text-align: center;
        color: #89b4fa;
        width: 1fr;
        text-style: bold;
        margin-bottom: 1;
    }

    LoginScreen #login-subtitle {
        text-align: center;
        color: #b4befe;
        width: 1fr;
        text-style: bold;
        margin-bottom: 2;
    }

    LoginScreen .login-label {
        margin-top: 1;
        text-align: center;
    }

    LoginScreen .login-input {
        background: #363a4f;
        border: round #6c7086;
        width: 100%;
    }

    LoginScreen .login-checkbox {
        margin-top: 1;
        background: #363a4f;
        border: round #6c7086;
    }

    LoginScreen .login-button-container {
        align: center middle;
        margin-top: 2;
        height: auto;
    }

    LoginScreen #login-button-login {
        text-style: bold;
        margin-right: 1;
    }

    LoginScreen #login-button-exit {
        text-style: bold;
        margin-left: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Center():
            with Vertical(classes="login-container"):
                yield Label("Doom", id="login-title")
                yield Label("Certificate Template Details Viewer", id="login-subtitle")

                yield Label("IP Address", classes="login-label")
                yield Input(placeholder="127.0.0.1", classes="login-input", id="ip-input")

                yield Label("Domain", classes="login-label")
                yield Input(placeholder="example.local", classes="login-input", id="domain-input")

                yield Label("Username", classes="login-label")
                yield Input(placeholder="john.doe", classes="login-input", id="username-input")

                yield Label("Password", classes="login-label")
                yield Input(placeholder="Summer@2025", classes="login-input", password=True, id="password-input")
                
                with Horizontal(classes="login-button-container"):
                    yield Button.success("Login", id="login-button-login")
                    yield Button.error("Exit", id="login-button-exit")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "login-button-exit":
            self.app.exit()

        if event.button.id == "login-button-login":
            ip = self.query_one("#ip-input").value
            domain = self.query_one("#domain-input").value
            username = self.query_one("#username-input").value
            password = self.query_one("#password-input").value
            
            login_data = {
                "ip": ip, 
                "domain": domain, 
                "username": username, 
                "password": password
            }
            
            loading_screen = LoadingScreen(login_data)
            self.app.push_screen(loading_screen)