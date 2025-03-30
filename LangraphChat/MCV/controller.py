from datetime import datetime
from MCV.modello import ChatModel, Message
from MCV.gui import ChatView
import time

class ChatController:
    def __init__(self, model: ChatModel, view: ChatView):
        self.model = model
        self.view = view
        self.view.set_send_callback(self.handle_send)
        
    def handle_send(self):
        user_input = self.view.get_input()
        if not user_input.strip():
            return
            
        # Create and display user message
        timestamp = datetime.now().strftime("%H:%M:%S")
        user_message = Message(user_input, True, timestamp)
        self.model.add_message(user_message)
        self.view.display_message(user_message)
        self.view.clear_input()
        time.sleep(0.2)
        # Get and display AI response
        ai_response = self.model.get_ai_response(user_input)
        if ai_response:
            timestamp = datetime.now().strftime("%H:%M:%S")
            ai_message = Message(ai_response, False, timestamp)
            self.model.add_message(ai_message)
            self.view.display_message(ai_message)