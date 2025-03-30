
import ttkbootstrap as tk
from ttkbootstrap import ttk, ScrolledText
from datetime import datetime
from dataclasses import dataclass
from MCV.modello import Message


class ChatView(tk.Window):
    def __init__(self):
        super().__init__()
        
        self.title("Chat Application")
        self.geometry("600x800")
        
        # Chat display area
        self.chat_display = ScrolledText(self, wrap=tk.WORD, height=30)
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Input frame
        input_frame = ttk.Frame(self)
        input_frame.pack(padx=10, pady=5, fill=tk.X)
        
        # Message input
        self.message_input = ttk.Entry(input_frame)
        self.message_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Send button
        self.send_button = ttk.Button(input_frame, text="Send")
        self.send_button.pack(side=tk.RIGHT, padx=5)
        
        # Bind return key to send
        self.message_input.bind("<Return>", lambda e: self.send_button.invoke())
        
    def display_message(self, message: Message):
        timestamp = message.timestamp
        sender = "You" if message.is_user else "Assistant"
        
        self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {message.content}\n\n")
        self.chat_display.see(tk.END)
        
    def get_input(self) -> str:
        return self.message_input.get()
    
    def clear_input(self):
        self.message_input.delete(0, tk.END)
        
    def set_send_callback(self, callback):
        self.send_button.config(command=callback)