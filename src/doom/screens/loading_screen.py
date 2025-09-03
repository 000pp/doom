import asyncio
from textual.app import ComposeResult
from textual.widgets import Label, Button
from textual.containers import Vertical, Center
from textual.screen import Screen

from doom.protocols.ldap import get_ldap_connection
from .main_screen import MainScreen

class LoadingScreen(Screen):
    DEFAULT_CSS = """
    LoadingScreen {
        background: #2d3748;
        align: center middle;
    }

    LoadingScreen .loading-container {
        width: 50%;
        height: auto;
        align: center middle;
    }

    LoadingScreen #loading-title {
        color: #4fc3f7;
        text-style: bold;
        margin-bottom: 1;
        text-align: center;
        width: 100%;
    }

    LoadingScreen #loading-subtitle {
        color: #b4befe;
        margin-bottom: 1;
        text-align: center;
        width: 100%;
    }

    LoadingScreen #status-label {
        color: #a0aec0;
        margin-top: 1;
        margin-bottom: 2;
        text-align: center;
        width: 100%;
    }

    LoadingScreen #cancel-button {
        width: 30%;
        margin-top: 2;
    }
    """

    def __init__(self, login_data=None):
        super().__init__()
        self.login_data = login_data or {}
        self.ldap_auth_task = None
        self.ldap_connection = None
        self.base_dn = None

    def compose(self) -> ComposeResult:
        with Center():
            with Vertical(classes="loading-container"):
                yield Label("Trying to authenticate...", id="loading-title")
                yield Label(f"Connecting to {self.login_data.get('ip', 'unknown')} as {self.login_data.get('username', 'unknown')}@{self.login_data.get('domain', 'unknown')}...", id="loading-subtitle")
                yield Label("", id="status-label")
                
                with Center():
                    yield Button("Cancel", variant="error", id="cancel-button")

    async def on_mount(self) -> None:
        self.ldap_auth_task = asyncio.create_task(self.authenticate_ldap())

    async def authenticate_ldap(self) -> None:
        status_label = self.query_one("#status-label")
        
        try:
            status_label.update("Attempting LDAP connection...")
            
            connection_result = await asyncio.to_thread(
                get_ldap_connection,
                host=self.login_data.get('ip', ''),
                username=self.login_data.get('username', ''),
                password=self.login_data.get('password', ''),
                domain=self.login_data.get('domain', '')
            )
            
            
            if connection_result:
                self.ldap_connection, self.base_dn = connection_result
                
                status_label.update("Authentication successful!")
                
                main_screen = MainScreen({
                    "connection": self.ldap_connection,
                    "base_dn": self.base_dn,
                    "user_data": self.login_data
                })
                self.app.push_screen(main_screen)
                
            else:
                status_label.update("Authentication failed!")
                await asyncio.sleep(5.0)
                self.app.pop_screen()
                
        except Exception as e:
            error_msg = str(e)
            
            if "Invalid credentials" in error_msg:
                status_label.update(f"Invalid credentials provided! - {error_msg}")
            elif "bind" in error_msg.lower():
                status_label.update(f"Failed to bind to LDAP server! - {error_msg}")
            elif "connection" in error_msg.lower():
                status_label.update(f"Cannot connect to LDAP server! - {error_msg}")
            else:
                status_label.update(f"Authentication error: {error_msg}")
            
            await asyncio.sleep(5.0)
            self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-button":
            if self.ldap_auth_task and not self.ldap_auth_task.done():
                self.ldap_auth_task.cancel()
            
            if self.ldap_connection:
                try:
                    self.ldap_connection.unbind()
                except:
                    pass
            
            self.app.pop_screen()