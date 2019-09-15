import asyncio
import random, sys

msg_send=b''
endgameflag=0

def create_container_contents(*escape_room_objects):
    return {obj.name: obj for obj in escape_room_objects}
    
def listFormat(object_list):
    l = ["a "+object.name for object in object_list if object["visible"]]
    return ", ".join(l)

class EscapeRoomObject:
    def __init__(self, name, **attributes):
        self.name = name
        self.attributes = attributes
        self.triggers = []
        
    def do_trigger(self, *trigger_args):
        return [event for trigger in self.triggers for event in [trigger(self, *trigger_args)] if event]
        
    def __getitem__(self, object_attribute):
        return self.attributes.get(object_attribute, False)
        
    def __setitem__(self, object_attribute, value):
        self.attributes[object_attribute] = value
        
    def __repr__(self):
        return self.name
        
class EscapeRoomCommandHandler:
    def __init__(self, room, player, output=print):
        self.room = room
        self.player = player
        self.output = output
        
    def _run_triggers(self, object, *trigger_args):
        for event in object.do_trigger(*trigger_args):
            self.output(event)
        
    def _cmd_look(self, look_args):
        look_result = None
        if len(look_args) == 0:
            object = self.room
        else:
            object = self.room["container"].get(look_args[-1], self.player["container"].get(look_args[-1], None))
        
        if not object or not object["visible"]:
            look_result = "You don't see that here."
        elif object["container"] != False and look_args and "in" == look_args[0]:
            if not object["open"]:
                look_result = "You can't do that! It's closed!"
            else:
                look_result = "Inside the {} you see: {}".format(object.name, listFormat(object["container"].values()))
        else:
            self._run_triggers(object, "look")
            look_result = object.attributes.get("description","You see nothing special")
        self.output(look_result)
        
    def _cmd_unlock(self, unlock_args):
        unlock_result = None
        if len(unlock_args) == 0:
            unlock_result = "Unlock what?!"
        elif len(unlock_args) == 1:
            unlock_result = "Unlock {} with what?".format(unlock_args[0])
        
        else:
            object = self.room["container"].get(unlock_args[0], None)
            unlock = False
            
            if not object or not object["visible"]:
                unlock_result = "You don't see that here."
            elif not object["keyed"] and not object["keypad"]:
                unlock_result = "You can't unlock that!"
            elif not object["locked"]:
                unlock_result = "It's already unlocked"
            
            elif object["keyed"]:
                unlocker = self.player["container"].get(unlock_args[-1], None)
                if not unlocker:
                    unlock_result = "You don't have a {}".format(unlock_args[-1])                    
                elif unlocker not in object["unlockers"]:
                    unlock_result = "It doesn't unlock."
                else:
                    unlock = True
                    
            elif object["keypad"]:
                # TODO: For later Exercise
                pass
            
            if unlock:
                unlock_result = "You hear a click! It worked!"
                object["locked"] = False
                self._run_triggers(object, "unlock", unlocker)
        self.output(unlock_result)
        
    def _cmd_open(self, open_args):
        """
???LINES MISSING
???LINES MISSING
        self.command_handler = self.command_handler_class(room, player, self.output)
        self.status = "created"
    
    def start(self):
        self.status = "playing"
        self.output("Where are you? You don't know how you got here... Were you kidnapped? Better take a look around")
        
    def command(self, command_string):
        global endgameflag
        if self.status == "void":
            self.output("The world doesn't exist yet!")
        elif self.status == "created":
            self.output("The game hasn't started yet!")
        elif self.status == "dead":
            self.output("You already died! Sorry!")
            endgameflag=1
        elif self.status == "escaped":
            self.output("You already escaped! The game is over!")
            endgameflag=1
        else:
            self.command_handler.command(command_string)
            if not self.player["alive"]:
                self.output("You died. Game over!")
                self.status = "dead"
                endgameflag=1
            elif self.player.name not in self.room["container"]:
                self.output("VICTORY! You escaped!")
                self.status = "escaped"
                endgameflag=1
        
def main():
    game = EscapeRoomGame()
    #game.create_game(cheat=("--cheat" in args))
    game.create_game()
    game.start()
    while game.status == "playing":
        command = input(">> ")
        output = game.command(command)

class EchoServer(asyncio.Protocol):
	def __init__(self, game=EscapeRoomGame()):
		self.game=game

	def connection_made(self, transport):
		self.transport = transport
		self.game.create_game()
		self.game.start()
		global msg_send
		self.transport.write(msg_send)
		msg_send=b''

	def data_received(self, data):
		print(data)
		if self.game.status == "playing":
			command=data.decode()
			cb=command.split('\n')
			for i in cb:
				if i!='':
					output = self.game.command(i[0:-5])
		global msg_send
		self.transport.write(msg_send)
		msg_send=b''
		if endgameflag==1:
			loop.stop()

if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = loop.create_server(EchoServer,'192.168.200.119',1810)
	server = loop.run_until_complete(coro)

	'''try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass'''
	loop.run_forever()

	loop.close()
import asyncio
import random, sys

msg_send=b''
endgameflag=0

def create_container_contents(*escape_room_objects):
    return {obj.name: obj for obj in escape_room_objects}
    
def listFormat(object_list):
    l = ["a "+object.name for object in object_list if object["visible"]]
    return ", ".join(l)

class EscapeRoomObject:
    def __init__(self, name, **attributes):
        self.name = name
        self.attributes = attributes
        self.triggers = []
        
    def do_trigger(self, *trigger_args):
        return [event for trigger in self.triggers for event in [trigger(self, *trigger_args)] if event]
        
    def __getitem__(self, object_attribute):
        return self.attributes.get(object_attribute, False)
        
    def __setitem__(self, object_attribute, value):
        self.attributes[object_attribute] = value
        
    def __repr__(self):
        return self.name
        
class EscapeRoomCommandHandler:
    def __init__(self, room, player, output=print):
        self.room = room
        self.player = player
        self.output = output
        
    def _run_triggers(self, object, *trigger_args):
        for event in object.do_trigger(*trigger_args):
            self.output(event)
        
    def _cmd_look(self, look_args):
        look_result = None
        if len(look_args) == 0:
            object = self.room
        else:
            object = self.room["container"].get(look_args[-1], self.player["container"].get(look_args[-1], None))
        
        if not object or not object["visible"]:
            look_result = "You don't see that here."
        elif object["container"] != False and look_args and "in" == look_args[0]:
            if not object["open"]:
                look_result = "You can't do that! It's closed!"
            else:
                look_result = "Inside the {} you see: {}".format(object.name, listFormat(object["container"].values()))
        else:
            self._run_triggers(object, "look")
            look_result = object.attributes.get("description","You see nothing special")
        self.output(look_result)
        
    def _cmd_unlock(self, unlock_args):
        unlock_result = None
        if len(unlock_args) == 0:
            unlock_result = "Unlock what?!"
        elif len(unlock_args) == 1:
            unlock_result = "Unlock {} with what?".format(unlock_args[0])
        
        else:
            object = self.room["container"].get(unlock_args[0], None)
            unlock = False
            
            if not object or not object["visible"]:
                unlock_result = "You don't see that here."
            elif not object["keyed"] and not object["keypad"]:
                unlock_result = "You can't unlock that!"
            elif not object["locked"]:
                unlock_result = "It's already unlocked"
            
            elif object["keyed"]:
                unlocker = self.player["container"].get(unlock_args[-1], None)
                if not unlocker:
        self.command_handler = self.command_handler_class(room, player, self.output)
        self.status = "created"
    
    def start(self):
        self.status = "playing"
        self.output("Where are you? You don't know how you got here... Were you kidnapped? Better take a look around")
        
    def command(self, command_string):
        global endgameflag
        if self.status == "void":
            self.output("The world doesn't exist yet!")
        elif self.status == "created":
            self.output("The game hasn't started yet!")
        elif self.status == "dead":
            self.output("You already died! Sorry!")
            endgameflag=1
        elif self.status == "escaped":
            self.output("You already escaped! The game is over!")
            endgameflag=1
        else:
            self.command_handler.command(command_string)
            if not self.player["alive"]:
                self.output("You died. Game over!")
                self.status = "dead"
                endgameflag=1
            elif self.player.name not in self.room["container"]:
                self.output("VICTORY! You escaped!")
                self.status = "escaped"
                endgameflag=1
        
def main():
    game = EscapeRoomGame()
    #game.create_game(cheat=("--cheat" in args))
    game.create_game()
    game.start()
    while game.status == "playing":
        command = input(">> ")
        output = game.command(command)

class EchoServer(asyncio.Protocol):
	def __init__(self, game=EscapeRoomGame()):
		self.game=game

	def connection_made(self, transport):
		self.transport = transport
		self.game.create_game()
		self.game.start()
		global msg_send
		self.transport.write(msg_send)
		msg_send=b''

	def data_received(self, data):
		print(data)
		if self.game.status == "playing":
			command=data.decode()
			cb=command.split('\n')
			for i in cb:
				if i!='':
					output = self.game.command(i[0:-5])
		global msg_send
		self.transport.write(msg_send)
		msg_send=b''
		if endgameflag==1:
			loop.stop()

if __name__ == "__main__":
	loop = asyncio.get_event_loop()
	coro = loop.create_server(EchoServer,'192.168.200.119',1810)
	server = loop.run_until_complete(coro)

	'''try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass'''
	loop.run_forever()

	loop.close()
