import tkinter as tk
from tkinter import font as tkfont


class Application(tk.Tk):
    def __init__(self):
        super().__init__()

        # --- win setting ---
        self.title("Гра із фігурою")
        self.geometry("600x400")
        self.minsize(400, 300)

        # --- build interface ---
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        # add the menus
        for F in (MainMenu, GameFrame):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(MainMenu)

    def show_frame(self, frame_class):
        """Raise the specified frame to the top"""
        frame = self.frames[frame_class]
        frame.tkraise()


class MainMenu(tk.Frame):
    COLORS = {
        "bg": "#2c3e50",
        "bt_play": "#3498db",
        "bt_exit": "#e74c3c",
        "text": "white"
    }

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # --- win setting ---
        self.configure(bg=self.COLORS["bg"])

        # centering elements
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # --- build interface ---
        # Title
        title_font = tkfont.Font(family="Helvetica", size=36, weight="bold")
        title = tk.Label(self, text="Фігура на сітці", font=title_font, bg=self.COLORS["bg"], fg=self.COLORS["text"])
        title.grid(row=1, column=0, pady=(20, 40))

        # Button "Play"
        btn_font = tkfont.Font(family="Helvetica", size=16)
        play_btn = tk.Button(self, text="Грати", font=btn_font, bg=self.COLORS["bt_play"], fg=self.COLORS["text"],
                             width=15, height=2, bd=0, highlightthickness=0,
                             command=lambda: controller.show_frame(GameFrame))
        play_btn.grid(row=2, column=0, pady=10)

        # Button "Exit"
        exit_btn = tk.Button(self, text="Вийти", font=btn_font, bg=self.COLORS["bt_exit"], fg=self.COLORS["text"],
                             width=15, height=2, bd=0, highlightthickness=0,
                             command=self.quit)
        exit_btn.grid(row=3, column=0, pady=10)

    def quit(self):
        self.controller.destroy()


class GameFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)


if __name__ == "__main__":
    app = Application()
    app.mainloop()