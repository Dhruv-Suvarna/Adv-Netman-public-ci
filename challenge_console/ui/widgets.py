"""Small ttk helpers shared by the views: a scrollable table and an in-place row synchroniser."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

OK, BAD, WARN, MUTED = "ok", "bad", "warn", "muted"
COLOURS = {OK: "#1b7f3b", BAD: "#b3261e", WARN: "#9a6700", MUTED: "#6b7280"}


def make_table(parent, columns: list[tuple], *, height: int = 10) -> tuple[ttk.Frame, ttk.Treeview]:
    """``columns``: (id, heading, width[, anchor]).  Returns (frame, treeview) with both scrollbars wired."""
    frame = ttk.Frame(parent)
    tree = ttk.Treeview(frame, columns=[column[0] for column in columns], show="headings", height=height, selectmode="browse")
    for column in columns:
        anchor = column[3] if len(column) > 3 else tk.W
        tree.heading(column[0], text=column[1], anchor=anchor)
        tree.column(column[0], width=column[2], minwidth=40, anchor=anchor, stretch=False)
    vertical = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
    horizontal = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    for tag, colour in COLOURS.items():
        tree.tag_configure(tag, foreground=colour)
    return frame, tree


def sync_table(tree: ttk.Treeview, rows: list[tuple]) -> None:
    """Make the table show ``rows`` -- (iid, values, tag) in order -- updating rows in place so selection and scroll survive."""
    wanted = [str(row[0]) for row in rows]
    existing = set(tree.get_children(""))
    for iid in existing - set(wanted):
        tree.delete(iid)
    for index, (iid, values, tag) in enumerate(rows):
        iid = str(iid)
        tags = (tag,) if tag else ()
        if iid in existing:
            tree.item(iid, values=values, tags=tags)
            if tree.index(iid) != index:
                tree.move(iid, "", index)
        else:
            tree.insert("", index, iid=iid, values=values, tags=tags)


def selected(tree: ttk.Treeview) -> str:
    chosen = tree.selection()
    return chosen[0] if chosen else ""


class View(ttk.Frame):
    """Base class of the five views.  ``refresh()`` re-renders from the store; it is only ever called on the Tk thread."""

    key = ""
    title = ""

    def __init__(self, parent, runtime):
        super().__init__(parent, padding=8)
        self.runtime, self.store, self.cfg = runtime, runtime.store, runtime.config   # (ttk.Frame.config is a method)
        self.renders = 0
        self.build()

    def build(self) -> None:
        raise NotImplementedError

    def render(self) -> None:
        raise NotImplementedError

    def refresh(self) -> None:
        self.renders += 1
        self.render()
