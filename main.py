import asyncio
from textual.app import App
from textual.binding import Binding

from doom.screens import LoginScreen

class DoomApp(App):
    """Doom - Certificate Template Details Viewer"""
    
    BINDINGS = [
        Binding(key="ctrl+q", action="quit", description="Quit the app"),
    ]

    def on_mount(self) -> None:
        self.title = "Doom - Certificate Template Viewer"
        self.sub_title = "LDAP Certificate Template Details Viewer"
        self.push_screen(LoginScreen())

if __name__ == "__main__":
    app = DoomApp()
    app.run()