from textual.app import ComposeResult
from textual.widgets import Label, Button, Footer, Tree
from textual.containers import Vertical, Center
from textual.screen import Screen

from doom.modules.enumerate_templates import enumerate_templates

class MainScreen(Screen):
    DEFAULT_CSS = """
    MainScreen {
        background: #1a202c;
        padding: 1;
    }

    MainScreen #main-title {
        text-align: center;
        color: #68d391;
        width: 1fr;
        text-style: bold;
        margin-bottom: 1;
    }

    MainScreen #server-info {
        text-align: center;
        color: #a0aec0;
        width: 1fr;
        margin-bottom: 1;
    }

    MainScreen #templates-tree {
        background: #1a202c;
        border: solid #4a5568;
        height: 1fr;
        margin-bottom: 1;
    }

    MainScreen .button-container {
        align: center middle;
        height: auto;
        margin-top: 1;
    }

    MainScreen #logout-button {
        text-style: bold;
        width: auto;
    }
    """

    def __init__(self, session_data=None):
        super().__init__()
        self.session_data = session_data or {}
        self.ldap_connection = self.session_data.get('connection')
        self.base_dn = self.session_data.get('base_dn')
        self.user_data = self.session_data.get('user_data', {})
        self.templates_data = {}
        self.expanded_templates = set()

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Doom - Certificate Template Viewer", id="main-title")
            yield Label(f"Server: {self.user_data.get('ip', 'Unknown')} | User: {self.user_data.get('username', 'Unknown')}@{self.user_data.get('domain', 'Unknown')}", id="server-info")
            
            tree = Tree("Certificate Templates", id="templates-tree")
            tree.root.expand()
            yield tree
            
            with Center(classes="button-container"):
                yield Button("Logout", variant="error", id="logout-button")
            
            yield Footer()

    async def on_mount(self) -> None:
        tree = self.query_one("#templates-tree")
        
        try:
            templates = await self.load_templates()
            
            if templates:
                await self.populate_tree(tree, templates)
            else:
                tree.root.add_leaf("No certificate templates found")
                
        except Exception as e:
            tree.root.add_leaf(f"Error loading templates: {str(e)}")

    async def load_templates(self):
        import asyncio
        
        return await asyncio.to_thread(
            enumerate_templates,
            self.ldap_connection,
            self.base_dn
        )

    async def populate_tree(self, tree, templates):
        for template in templates:
            template_name = template.get('name', 'Unknown Template')
            display_name = template.get('display_name', template_name)
            
            if display_name != template_name:
                label = f"{display_name} ({template_name})"
            else:
                label = template_name
                
            template_node = tree.root.add(label, allow_expand=True)
            self.templates_data[template_node.id] = template

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if event.node.id in self.templates_data and event.node.id not in self.expanded_templates:
            template = self.templates_data[event.node.id]
            self.add_template_details(event.node, template)
            self.expanded_templates.add(event.node.id)
            event.node.expand()

    def add_template_details(self, template_node, template):
        combined_attrs = template.get('attributes', {})
        
        details_node = template_node.add("Template Details")
        
        for attr_name in sorted(combined_attrs.keys()):
            value = combined_attrs[attr_name]
            
            if isinstance(value, bool):
                status = "Yes" if value else "No"
                formatted_key = attr_name.replace('_', ' ').title()
                details_node.add_leaf(f"{formatted_key}: {status}")
            
            elif isinstance(value, list):
                if len(value) == 0:
                    details_node.add_leaf(f"{attr_name}: [empty]")
                else:
                    attr_node = details_node.add(f"{attr_name}: [{len(value)} items]")
                    for i, item in enumerate(value):
                        item_str = str(item)
                        if len(item_str) > 100:
                            item_str = item_str[:100] + "..."
                        attr_node.add_leaf(f"[{i}]: {item_str}")
            
            else:
                display_value = str(value)
                if len(display_value) > 100:
                    display_value = display_value[:100] + "..."
                details_node.add_leaf(f"{attr_name}: {display_value}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "logout-button":
            if self.ldap_connection:
                try:
                    self.ldap_connection.unbind()
                except:
                    pass
            
            self.app.pop_screen()
            self.app.pop_screen()