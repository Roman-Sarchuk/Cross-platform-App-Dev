from random import choice as randchoice
from enum import Enum, auto
import re
import tkinter as tk
from PIL import Image, ImageTk
import spacy
from sentence_transformers import SentenceTransformer, util


# colors
COLORS = {
    "header_bg": "#fadda2",
    "chat_bg": "#f0eff4",
    "user_msg_bg": "#8ecde6",
    "bot_msg_bg": "#66a1fa",
    "input_bar_bg": "#444",
}
# character data
CHARACTERS_DATA = {
    "Bobrito Bandito": {
        "description": "Ти — життєрадісний авантюрист із шармом бандита. Твоя харизма, гумор і любов до пригод роблять тебе душею компанії. Ти вмієш знаходити вихід з будь-якої ситуації, додаючи їй пікантності та веселощів.",
        "keywords": ["авантюра", "гумор", "харизма", "пригоди", "енергійність", "холоднокровність", "ризик"],
    },
    "Shpioniro Golubiro": {
        "description": "Ти — уважний спостерігач, який завжди на крок попереду. Твоя серйозність і здатність помічати деталі роблять тебе майстром аналізу. Ти вмієш зберігати спокій навіть у найнапруженіших ситуаціях.",
        "keywords": ["спостережливість", "аналітичність", "серйозність", "обережність", "інтелект", "скритність"],
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
for key in CHARACTERS_DATA.keys():
    CHARACTERS_DATA[key]["image_path"] = f"images//{key}.png"
# bot response
GREETING = """
👋 Привіт!
Я — твій персональний мемолог-аналітик, і я допоможу визначити, на якого італійського мемного персонажа ти найбільше схожий 😎
Усе просто: я поставлю тобі кілька веселих, але трохи філософських запитань. Відповідай чесно, з гумором або як відчуваєш — і на основі твоїх відповідей я проаналізую твою енергетику, стиль мислення та вайб 🌀
У фіналі ти отримаєш мем-альтер-его, яке найточніше резонує з твоєю сутністю ✨
Готовий(-а)? Тоді почнімо 🔥
"""
QUESTIONS = [
    "Як ти зазвичай реагуєш у стресовій ситуації?",
    "Наскільки важливо для тебе бути смішним або веселим у компанії?",
    "Чи вважаєш себе більш мрійливою або більш раціональною особистістю?",
    "Як ти ставишся до хаосу та несподіванок у повсякденному житті?",
    "Наскільки часто ти задумуєшся про дивні або абсурдні речі просто так?",
    "Як ти зазвичай взаємодієш з іншими людьми?",
    "Що тобі ближче — музика, наука чи мода?",
    "Чи відчуваєш ти потяг до пригод і спонтанних подій?",
    "Ти більше відчуваєш себе лідером чи спостерігачем?",
    "Наскільки тобі комфортно бути в центрі уваги?",
    "Чи вважаєш ти, що в тобі поєднуються контрастні риси характеру?",
    "Як часто ти імпровізуєш у щоденних ситуаціях?",
    "Чи буває, що ти говориш або дієш дуже швидко, ніби за шаблоном?",
    "Наскільки ти чутливий до естетики, кольорів, стилю?",
    "Як ти ставишся до абсурдного гумору або мемів без сенсу?",
    "Чи вважаєш себе більш дитячим чи дорослим за духом?",
    "Чи доводилося тобі вигадувати щось дуже дивне — пісню, істоту, ім’я?",
    "Як ти ставишся до рутинних, ритмічних завдань?",
    "Чи часто ти ведеш себе ніби в грі або фантазійному світі?",
    "Що тебе більше описує: точність, натхнення чи інтуїція?"
]
TOO_SHORT_RESPONSES = [
    "О, ну це трохи замало! Скажи більше 🧐",
    "Не бійся розгорнути думку — я слухаю уважно 😉",
    "Це тільки натяк... Розгорни думку повністю!",
    "Хм, хочеться більше слів, щоб зрозуміти тебе краще!",
    "Дай трішки більше деталей — це важливо для точного результату!"
]
GIBBERISH_RESPONSES = [
    "Спробуй відповісти трішки докладніше — щоб я краще тебе зрозумів!",
    "Можливо, трохи більше сенсу в наступній відповіді? 🤔",
    "Я люблю сюрреалізм, але давай все ж трохи змісту 😅",
    "Твоя відповідь звучить як пісня з космосу — поясниш її?",
    "Можеш сказати це ще раз, але зрозуміліше?"
]
MEANINGFUL_RESPONSES = [
    "Цікаво! Я вже думаю, хто ти з моїх персонажів...",
    "О, це вже дещо! Продовжуй, дуже пізнавально 😎",
    "Твоя відповідь допомагає краще побачити твій стиль мислення!",
    "Окей, записав це в особистий профіль — далі буде ще цікавіше!",
    "Добре сказано! Продовжуй у тому ж дусі 💡"
]


class BotState(Enum):
    GREETING = auto()
    QUESTION = auto()
    WAIT_ANSWER = auto()
    RESULT = auto()
    DONE = auto()


class Bot:
    def __init__(self):
        self.questions = QUESTIONS.copy()
        self.state = BotState.GREETING

        self.nlp = spacy.load("uk_core_news_sm")
        self.transformer_model = SentenceTransformer("paraphrase-MiniLM-L6-v2")
        self.character_embeddings = {
            k: self.transformer_model.encode(", ".join(v["keywords"]))
            for k, v in CHARACTERS_DATA.items()
        }

        self.user_profile = {k: 0 for k in CHARACTERS_DATA.keys()}

    def __pop_rand_question(self):
        if self.questions:
            question = randchoice(self.questions)
            self.questions.remove(question)
            return question

        return None

    def get_greeting(self) -> str:
        if self.state == BotState.GREETING:
            self.state = BotState.QUESTION
            return GREETING
        return str()

    def get_question(self) -> str:
        if self.state == BotState.QUESTION:
            question = self.__pop_rand_question()
            if question:
                self.state = BotState.WAIT_ANSWER
                return question
            else:
                self.state = BotState.RESULT
        return str()

    def get_result(self) -> dict:
        if self.state == BotState.RESULT:
            meme = max(self.user_profile, key=self.user_profile.get)
            self.state = BotState.DONE
            return {"meme": meme, "description": CHARACTERS_DATA[meme]["description"], "image_src": Image.open(CHARACTERS_DATA[meme]["image_path"])}
        return dict()

    def get_response(self, message) -> str:
        if self.state == BotState.WAIT_ANSWER:
            verification_text = self.verify_message(message)
            if verification_text:
                return verification_text

            msg_scores = self.analyze_message(message)
            for meme, score in msg_scores.items():
                self.user_profile[meme] += score

            self.state = BotState.QUESTION
            return randchoice(MEANINGFUL_RESPONSES)
        return str()

    def analyze_message(self, message):
        user_vector = self.transformer_model.encode(message)
        scores = {
            meme: util.cos_sim(user_vector, emb)[0][0].item()
            for meme, emb in self.character_embeddings.items()
        }
        return scores

    def is_early_result_possible(self, threshold=0.60, dominance_margin=0.15) -> bool:
        # total = sum(self.user_profile.values())
        # if total == 0:
        #     return False  # nothing has been collected yet
        #
        # meme_scores = {k: v / total for k, v in self.user_profile.items()}
        # top_meme, top_score = max(meme_scores.items(), key=lambda x: x[1])
        # second_score = sorted(meme_scores.values(), reverse=True)[1]
        # # print(f"{top_meme}-{int(top_score*10000)/100}% | {int(second_score*10000)/100}%")
        #
        # # if the most popular meme exceeds the threshold and is ahead of the next one by a margin
        # if top_score >= threshold and (top_score - second_score) >= dominance_margin:
        #     return True
        # return False
        # print(f"{len(QUESTIONS)} > {len(self.questions)} / {len(QUESTIONS) // 1.2}")
        if self.state != BotState.DONE:
            return len(self.questions) <= len(QUESTIONS) // 1.1
        return False

    def set_result_state(self):
        self.state = BotState.RESULT
        self.questions = []

    # ----- content relevance check -----
    @staticmethod
    def is_gibberish(text):
        pattern = r'^[^a-zA-Zа-яА-ЯіІїЇєЄґҐ0-9]{3,}$'  # only symbols & emoji
        return bool(re.match(pattern, text.strip()))

    def has_meaningful_words(self, text):
        doc = self.nlp(text)
        return any(tok.pos_ in ["NOUN", "VERB", "ADJ"] for tok in doc)

    def verify_message(self, message) -> str:
        if len(message.strip().split()) < 3:
            return randchoice(TOO_SHORT_RESPONSES)

        if self.is_gibberish(message) or not self.has_meaningful_words(message):
            return randchoice(GIBBERISH_RESPONSES)

        return ""
    # ----- ------- --------- ----- -----


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Italian brainrot")
        self.geometry("400x500")
        self.configure(bg=COLORS["chat_bg"])

        # values
        self.message_labels = []    # for message resizing
        self.input_msg_var = tk.StringVar()
        self.bot = Bot()
        self.is_skip_button_shown = False
        self.img_results = []

        self.build_interface()

        self._send_initial_bot_message()

    def build_interface(self):
        # --- header ---
        header_frame = tk.Frame(self, bg=COLORS["header_bg"])
        header_frame.pack(side=tk.TOP, fill=tk.X)

        title_frame = tk.Frame(header_frame, bg=COLORS["header_bg"])
        title_frame.pack(side=tk.LEFT)

        bot_icon_src = Image.open("images\\bot_icon.png")
        self.bot_icon = ImageTk.PhotoImage(bot_icon_src.resize((40, 40)))

        label_icon = tk.Label(title_frame, image=self.bot_icon, text="🖼", bg=COLORS["header_bg"])
        label_icon.grid(row=0, column=0, padx=10, pady=2)

        label_title = tk.Label(title_frame, text="Memzer UA", bg=COLORS["header_bg"], font=("consolas", 15))
        label_title.grid(row=0, column=1, padx=10)

        self.skip_button = tk.Button(header_frame, text="Skip the Rest", command=self.__on_skip_button)

        self.restart_button = tk.Button(header_frame, text="Restart", command=self.__on_restart_button)

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
        message_entry.bind("<Return>", self.send_message)
        send_button = tk.Button(
            input_bar, command=self.send_message,
            text="🔼"
        )

        send_button.pack(side=tk.RIGHT, padx=(5,10))
        message_entry.pack(fill=tk.X, expand=True, padx=10)

    def __on_canvas_resize(self, event):
        self.canvas.itemconfig(self.scrollable_frame, width=event.width)

        for label in self.message_labels:
            label.config(wraplength=event.width//2)

    def __on_skip_button(self):
        self.bot.set_result_state()
        self.input_msg_var.set("На цьому зупинимося, дай результат вже на поточних даних!")
        self.send_message()

    def __on_restart_button(self):
        for widget in self.chat_frame.winfo_children():
            widget.destroy()
        self.message_labels.clear()
        self.input_msg_var.set("")

        self.restart_button.pack_forget()
        if self.is_skip_button_shown:
            self.skip_button.pack_forget()

        self.bot = Bot()
        self._send_initial_bot_message()

    def _send_initial_bot_message(self):
        self.add_message(self.bot.get_greeting(), from_user=False)
        question = self.bot.get_question()
        self.add_message(question, from_user=False)

    def send_message(self, event=None):
        user_message = self.input_msg_var.get()
        if user_message:
            # user message
            self.add_message(user_message, from_user=True)
            self.input_msg_var.set("")

            # bot response
            response = self.bot.get_response(user_message)
            self.add_message(response, from_user=False)

            # bot question
            question = self.bot.get_question()
            if question:
                self.add_message(question, from_user=False)
            else:
                # bot result
                result = self.bot.get_result()
                if result:
                    self.add_img_message(
                        title=result["meme"],
                        img_src=result["image_src"],
                        text=result["description"]
                    )
                    self.skip_button.pack_forget()
                    self.is_skip_button_shown = False
                    self.restart_button.pack(side=tk.RIGHT, padx=10, pady=10)
                    return

            # skip button
            if not self.is_skip_button_shown and self.bot.is_early_result_possible():
                self.skip_button.pack(side=tk.RIGHT, padx=10, pady=10)
                self.is_skip_button_shown = True
            # elif self.is_skip_button_shown:
            #     self.skip_button.pack_forget()
            #     self.is_skip_button_shown = False

    def add_message(self, message, from_user):
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

    def add_img_message(self, title, img_src, text, from_user=False):
        if title or img_src or text:
            container = tk.Frame(self.chat_frame, bg=COLORS["chat_bg"])
            container.pack(side=tk.TOP, fill=tk.X, expand=True)

            if title:
                title_label = tk.Label(
                    container, text=title, justify=tk.CENTER,
                    bg=COLORS["user_msg_bg"] if from_user else COLORS["bot_msg_bg"],
                    wraplength=self.canvas.winfo_width() // 2
                )
                title_label.pack(padx=10, pady=2, ipadx=5, ipady=5, anchor="e" if from_user else "w")
                self.message_labels.append(title_label)

            if img_src:
                size = min(self.canvas.winfo_width() // 2, 100)
                img = ImageTk.PhotoImage(img_src.resize((size, size)))
                self.img_results.append(img)

                img_label = tk.Label(
                    container, image=self.img_results[-1], justify=tk.LEFT,
                    bg=COLORS["user_msg_bg"] if from_user else COLORS["bot_msg_bg"]
                )
                img_label.pack(padx=10, pady=2, ipadx=5, ipady=5, anchor="e" if from_user else "w")
                self.message_labels.append(img_label)

            if text:
                text_label = tk.Label(
                    container, text=text, justify=tk.LEFT,
                    bg=COLORS["user_msg_bg"] if from_user else COLORS["bot_msg_bg"],
                    wraplength=self.canvas.winfo_width() // 2
                )
                text_label.pack(padx=10, pady=2, ipadx=5, ipady=5, anchor="e" if from_user else "w")
                self.message_labels.append(text_label)

            self.canvas.yview_moveto(1.0)


if __name__ == "__main__":
    app = Application()
    app.mainloop()
