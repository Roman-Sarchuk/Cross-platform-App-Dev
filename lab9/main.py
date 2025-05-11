import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from random import choice as randchoice

# colors
COLORS = {
    "header_bg": "#A4A",
    "chat_bg": "#999",
    "user_msg_bg": "#85993C",
    "bot_msg_bg": "#6A8DA9",
    "input_bar_bg": "#444",
}
# values
GREETING = """
👋 Привіт!
Я — твій персональний мемолог-аналітик, і я допоможу визначити, на якого італійського мемного персонажа ти найбільше схожий 😎
Усе просто: я поставлю тобі кілька веселих, але трохи філософських запитань. Відповідай чесно, з гумором або як відчуваєш — і на основі твоїх відповідей я проаналізую твою енергетику, стиль мислення та вайб 🌀
У фіналі ти отримаєш мем-альтер-его, яке найточніше резонує з твоєю сутністю ✨
Готовий(-а)? Тоді почнімо 🔥
"""
QUESTIONS = [
    "Як би ти описав свій настрій у трьох словах?",
    "Ти більше мрійник, логік чи божевільний експериментатор?",
    "Яку тварину ти б обрав як свій символ?",
    "Чи любиш ти порядок, чи повний хаос?",
    "Що тебе більше приваблює: музика, гумор, магія чи наука?",
    "Твоя ідеальна реакція на конфлікт — жарт, втеча, атака чи ігнор?",
    "Тобі ближче граційність, сила, швидкість чи загадковість?",
    "Якщо б тебе запросили в мультфільм — яким був би твій голос?",
    "Ти більше про логіку чи емоції?",
    "Якби ти був персонажем, ти б був героєм, антигероєм чи просто диваком?"
]
CHARACTERS = {
    "Bobrito Bandito": {
        "description": "Ти — життєрадісний авантюрист із шармом бандита. Твоя харизма, гумор і любов до пригод роблять тебе душею компанії. Ти вмієш знаходити вихід з будь-якої ситуації, додаючи їй пікантності та веселощів.",
        "keywords": ["авантюра", "гумор", "харизма", "пригоди", "енергійність", "холоднокровність", "ризик"],
    },
    "Shpioniro Golubiro": {
        "description": "Ти — уважний спостерігач, який завжди на крок попереду. Твоя серйозність і здатність помічати деталі роблять тебе майстром аналізу. Ти вмієш зберігати спокій навіть у найнапруженіших ситуаціях.",
        "keywords": ["спостережливість", "аналітичність", "серйозність", "обережність", "інтелект"],
    },
    "Cappuccino Asassino": {
        "description": "Ти — поєднання витонченості та рішучості. Зовні ти спокійний і привабливий, але всередині приховуєш силу та цілеспрямованість. Твоя двозначність робить тебе загадковим і привабливим для оточуючих.",
        "keywords": ["витонченість", "рішучість", "загадковість", "спокій", "цілеспрямованість"],
    },
    "Tralalero Tralala": {
        "description": "Ти — втілення радості та безтурботності. Твоя любов до музики і здатність знаходити позитив у всьому роблять тебе джерелом натхнення для інших. Ти вмієш перетворювати буденність на свято.",
        "keywords": ["радість", "музика", "оптимізм", "творчість", "безтурботність"],
    },
    "Crocodildo Penisini": {
        "description": "Ти — поєднання дикості та гумору. Твоя здатність ламати стереотипи і провокувати сміх робить тебе незабутнім. Ти не боїшся бути собою і вражати оточуючих своєю унікальністю.",
        "keywords": ["гумор", "дикість", "самовираження", "провокація", "унікальність"],
    },
    "Lirili Larila": {
        "description": "Ти — мрійник з багатою уявою. Твоя ніжність і любов до фантазійного світу роблять тебе чарівним і привабливим. Ти вмієш бачити красу в дрібницях і надихати інших на мрії.",
        "keywords": ["мрійливість", "фантазія", "ніжність", "чарівність", "інтуїція"],
    },
    "Boneca Ambalabu": {
        "description": "Ти — втілення креативності та нестандартного мислення. Твоя любов до абсурду і здатність бачити світ під іншим кутом роблять тебе унікальним. Ти вмієш знаходити радість у несподіваному.",
        "keywords": ["креативність", "абсурд", "нестандартність", "гумор", "уява"],
    },
    "U Din Din Din Dun": {
        "description": "Ти — енергійний та організований. Твоя здатність підтримувати ритм і діяти злагоджено робить тебе надійним партнером. Ти вмієш ефективно працювати в команді та досягати поставлених цілей.",
        "keywords": ["енергійність", "організованість", "ритм", "надійність", "ефективність", "дисципліна", "м'язи"],
    },
    "Bri Bri Bicus Discus": {
        "description": "Ти — інтелектуал з нестандартним мисленням. Твоя любов до знань і здатність бачити глибокі зв'язки роблять тебе цікавим співрозмовником. Ти вмієш поєднувати логіку з креативністю.",
        "keywords": ["інтелект", "креативність", "аналітичність", "дослідник", "новаторство"],
    },
    "Ballerina Cappuccina": {
        "description": "Ти — поєднання грації та пристрасті. Твоя витонченість і емоційність роблять тебе яскравою особистістю. Ти вмієш виражати себе через рух і надихати інших своєю енергією.",
        "keywords": ["грація", "емоційність", "енергія", "виразність", "натхнення"],
    },
    "Bluberini Octopussini": {
        "description": "Ти — відкритий і контактний. Твоя здатність встановлювати зв'язки і адаптуватися до нових ситуацій робить тебе цінним членом будь-якої спільноти. Ти вмієш знаходити спільну мову з різними людьми.",
        "keywords": ["комунікабельність", "адаптивність", "дружелюбність", "гнучкість", "емпатія"],
    },
    "Brr Brr Patapim": {
        "description": "Ти — енергійний і грайливий. Твоя здатність перетворювати буденність на гру і знаходити радість у простих речах робить тебе джерелом позитиву для оточуючих.",
        "keywords": ["енергійність", "грайливість", "оптимізм", "творчість", "дитячість"],
    },
    "Bambini Crossini": {
        "description": "Ти — стильний і впевнений у собі. Твоя здатність поєднувати дитячу безпосередність з дорослою серйозністю робить тебе унікальним. Ти вмієш привертати увагу і залишати яскраве враження.",
        "keywords": ["стиль", "впевненість", "харизма", "унікальність", "самовираження"],
    },
    "Ketupat Kepat Prekupat Kepat Kepet Kepot": {
        "description": "Ти — втілення хаосу і креативності. Твоя здатність створювати нове з нічого і бачити світ у незвичних формах робить тебе джерелом натхнення для інших. Ти вмієш ламати стереотипи і відкривати нові горизонти.",
        "keywords": ["креативність", "хаос", "інновації", "нестандартність", "натхнення"],
    },
    "Tung Tung Tung Tung Tung Tung Sahur": {
        "description": "Ти — ритмічний і наполегливий. Твоя здатність підтримувати темп і мотивувати інших робить тебе лідером. Ти вмієш організовувати процеси і досягати поставлених цілей.",
        "keywords": ["ритм", "наполегливість", "організованість", "мотивація", "лідерство"],
    }
}

for key in CHARACTERS.keys():
    CHARACTERS[key]["image_path"] = f"images//{key}.png"


class Bot:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self.questions = QUESTIONS.copy()

            self._initialized = True

    def __get_rand_question(self):
        if self.questions:
            question = randchoice(self.questions)
            self.questions.remove(question)
            return question

        return None

    def get_greeting(self):
        return GREETING

    def get_question(self):
        question = self.__get_rand_question()
        if question:
            return question

    def get_result(self):
        pass

    def receive_message(self, message):
        self.get_question()


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Italian brainrot")
        self.geometry("400x500")

        self.message_labels = []
        self.bot = Bot()
        self.input_msg_var = tk.StringVar()

        self.build_interface()

        self.add_message(self.bot.get_greeting(), from_user=False)
        question = self.bot.get_question()
        self.add_message(question, from_user=False)

    def build_interface(self):
        # --- header ---
        header_frame = tk.Frame(self, bg=COLORS["header_bg"])
        header_frame.pack(side=tk.TOP, fill=tk.X)

        bot_icon_src = Image.open("images\\bot_icon.png")
        self.bot_icon = ImageTk.PhotoImage(bot_icon_src.resize((40, 40)))

        label_icon = tk.Label(header_frame, image=self.bot_icon, text="🖼", bg=COLORS["header_bg"])
        label_icon.grid(row=0, column=0, padx=10, pady=2)

        label_title = tk.Label(header_frame, text="Memzer UA", bg=COLORS["header_bg"], font=("consolas", 15))
        label_title.grid(row=0, column=1, padx=10)

        # --- scrolable frame ---
        # Основна область для чату
        content_frame = tk.Frame(self)
        content_frame.pack(fill="both", expand=True)

        # Створюємо полотно (Canvas) з прокруткою
        self.canvas = tk.Canvas(content_frame, bg=COLORS["chat_bg"])
        scrollbar = tk.Scrollbar(content_frame, orient="vertical", command=self.canvas.yview)
        self.chat_frame = tk.Frame(self.canvas, bg=COLORS["chat_bg"], pady=10)

        # Прив'язка прокрутки
        __on_frame_configure = lambda event: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.chat_frame.bind("<Configure>", __on_frame_configure)
        __on_mousewheel = lambda event: self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        self.canvas.bind_all("<MouseWheel>", __on_mousewheel)

        # Вбудовуємо scrollable_frame у canvas
        self.scrollable_frame = self.canvas.create_window((0, 0), window=self.chat_frame)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.bind("<Configure>", self.__on_canvas_resize)

        # Розміщення
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # --- input bar ---
        input_bar = tk.Frame(self, bg=COLORS["input_bar_bg"])
        input_bar.pack(side=tk.BOTTOM, fill=tk.X, ipady=5, ipadx=5)

        message_entry = tk.Entry(input_bar, textvariable=self.input_msg_var)
        message_entry.bind("<Return>", self.send_answer)
        send_button = tk.Button(
            input_bar, command=self.send_answer,
            text="🔼"
        )

        send_button.pack(side=tk.RIGHT, padx=(5,10))
        message_entry.pack(fill=tk.X, expand=True, padx=10)

        # --- TODO: test button ---
        test_b_frame = tk.Frame(self, bg="#fff")

        send_question_b = tk.Button(
            test_b_frame, command=lambda: self.bot.get_question,
            text="Question"
        )
        send_res_b = tk.Button(
            test_b_frame, command=lambda: self.bot.send_result,
            text="Result"
        )

        test_b_frame.pack(side=tk.BOTTOM, fill=tk.X)
        send_question_b.pack(side=tk.LEFT)
        send_res_b.pack(side=tk.LEFT)

    def __on_canvas_resize(self, event):
        self.canvas.itemconfig(self.scrollable_frame, width=event.width)

        for label in self.message_labels:
            label.config(wraplength=event.width//2)

    def send_answer(self, event=None):
        message = self.input_msg_var.get()
        if message:
            self.add_message(message)
            self.input_msg_var.set("")

            question = self.bot.get_question()
            self.add_message(question, from_user=False)

    def add_message(self, message, from_user=True):
        if message:
            container = tk.Frame(self.chat_frame, bg=COLORS["chat_bg"])
            container.pack(side=tk.TOP, fill=tk.X, expand=True)
            label = tk.Label(
                container, text=message, justify=tk.LEFT,
                bg=COLORS["user_msg_bg"] if from_user else COLORS["bot_msg_bg"],
                wraplength=self.canvas.winfo_width()//2
            )
            label.pack(padx=10, pady=2, ipadx=5, ipady=5, anchor="e" if from_user else "w")
            self.message_labels.append(label)
            self.canvas.yview_moveto(1.0)


if __name__ == "__main__":
    app = Application()
    app.mainloop()
