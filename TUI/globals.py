import os
import re
import sys
import queue
import time
import threading
from textual.app import App, ComposeResult
from textual.containers import(
    Container,
    Horizontal, 
    Vertical, 
    ScrollableContainer
)

from textual.widgets import (
    Header,
    Footer,
    Static,
    Button,
    Label,
    Input,
    Select,
    TabbedContent,
    TabPane,
    DirectoryTree,
    TextArea,
    RichLog,
)

from textual.screen import ModalScreen
from textual.widgets import RadioButton
from textual.binding import Binding

from textual.theme import Theme
from textual.color import Color
from rich.syntax import Syntax
from rich.text import Text
from rich.console import Console
from textual.widgets._text_area import TextAreaTheme

from ROM_rw.diassembler import disassemble_esp8266_full

galaxy_primary = Color.parse("#C4A7F7")
galaxy_secondary = Color.parse("#a684e8")
galaxy_warning = Color.parse("#af9b28")
galaxy_error = Color.parse("#FF4500")
galaxy_success = Color.parse("#00cc7e")
galaxy_accent = Color.parse("#FF69B4")
galaxy_background = Color.parse("#0F0F1F")
galaxy_surface = Color.parse("#1E1E3F")
galaxy_panel = Color.parse("#2D2B55")
galaxy_contrast_text = galaxy_background.get_contrast_text(1.0)

GALAXY_THEME = Theme(
    name="galaxy",
    primary=galaxy_primary.hex,
    secondary=galaxy_secondary.hex,
    warning=galaxy_warning.hex,
    error=galaxy_error.hex,
    success=galaxy_success.hex,
    accent=galaxy_accent.hex,
    background=galaxy_background.hex,
    surface=galaxy_surface.hex,
    panel=galaxy_panel.hex,
    dark=True,
    variables={
        "input-cursor-background": "#C45AFF",
        "footer-background": "transparent",
    },
)