#
# Copyright 2014 Cumulus Networks, Inc. All rights reserved.
# Author:   Julien Fortin <julien.fortin.it@gmail.com>
#           Alexandre Renard <arenardvv@gmail.com>
#
# pyjeet --
# the distributed log analysis tool for networking troubleshooting.
#


import curses
import sys
from abc import ABCMeta, abstractmethod
import time
from datetime import datetime
import math
import threading
import logging
logging.basicConfig(filename='/var/log/pyjeet.log',level=logging.DEBUG)


class Gui:
    def __init__(self):
        self.window = curses.initscr()
        # Basic layout information
        self.info = Information()
        self.info.line_add("Pyjeet version 2.5", (0, 0), "top-left", self.window)
        helpm = str(datetime.now()).split('.')[0]
        self.info.line_add(helpm, (0, len(helpm)), "top-right", self.window)

        # Menu
        self.menu = Menu()
        # Add fields to the menu
        line6 = Line("Find log info for this vlan:", (6, 0), "bottom-left", self.window)
        item6 = Field(line6, 50, "vlan")
        self.menu.add_field(item6)

        line5 = Line("Find log info for this bridge:", (5, 0), "bottom-left", self.window)
        item5 = Field(line5, 50, "bridge")
        self.menu.add_field(item5)

        line1 = Line("Find log info for this grep pattern:", (4, 0), "bottom-left", self.window)
        item1 = Field(line1, 50, "grep")
        self.menu.add_field(item1)

        line2 = Line("Find log info for this ip address:", (3, 0), "bottom-left", self.window)
        item2 = Field(line2, 50, "ip")
        self.menu.add_field(item2)

        line3 = Line("Find log info for this interface:", (2, 0), "bottom-left", self.window)
        item3 = Field(line3, 50, "interface")
        self.menu.add_field(item3)

        line4 = Line("Find log info at this time:", (1, 0), "bottom-left", self.window)
        item4 = Field(line4, 50, "time")
        self.menu.add_field(item4)

        # Body created on the fly
        self.body = None

        # Buffer stack to hold previous bodies
        self.buffer_body = []

    # loading function runs in a thread
    def loading(self, normalized_logs, num_chunks):
        # window dimensions
        (y, x) = self.window.getmaxyx()
        #  display rocket turtle
        self.info.line_add("      _______   x x x", (y/2 - 3, x/2 - 10), "top-left", self.window) 
        self.info.line_add(" ._  <_______~ x X x ", (y/2 - 3 + 1, x/2 - 10), "top-left", self.window) 
        self.info.line_add("(' \  ,' || `,       ", (y/2 - 3 + 2, x/2 - 10), "top-left", self.window) 
        self.info.line_add(" `._:^   ||   :>     ", (y/2 - 3 + 3, x/2 - 10), "top-left", self.window) 
        self.info.line_add("     ^T~~~~~~T'      ", (y/2 - 3 + 4, x/2 - 10), "top-left", self.window) 
        self.info.line_add("     ~\"     ~\"       ", (y/2 - 3 + 5, x/2 - 10), "top-left", self.window) 
        self.info.display()
        self.window.refresh()
        step = int(math.ceil(x/float(num_chunks)))
        while 42:
	    # python list is deadlock safe
            self.window.chgat(0, 0, normalized_logs['current_chunk']*step, curses.A_REVERSE)
            self.window.refresh()
            time.sleep(0.1)
            if normalized_logs['current_chunk'] >= num_chunks:
                self.window.chgat(0, 0, curses.A_NORMAL)
                for i in range(6):
                    self.info.remove_last()
                return

    def run(self, output, cap):
        try:
            self.catch_wating_thread()
            # Turn off echoing of keys, and enter cbreak mode,
            # where no char_countering is performed on keyboard input
            curses.noecho()
            curses.cbreak()

            # In keypad mode, escape sequences for special keys
            # (like the cursor keys) will be interpreted and
            # a special value like curses.KEY_LEFT will be returned
            self.window.keypad(1)

            while 42:
                self.display_basics()
                self.display_status(output)
                if not output:
                    result = self.start_on_menu()
                else:
                    self.set_display_body(output, cap)
                    # wait for user input
                    c = self.window.getch()
                    #Escape Key
                    if c == 0x1b:
                        output = self.go_back(output)
                        continue
                    elif c == curses.KEY_RESIZE:
                        logging.error('Resizing terminal is not supported in this version')
                        sys.exit(1)
                    else:
                        result = self.body.action(c)
                if isinstance(result, Request):
                    time.sleep(0.1)
                    return result
        finally:
            self.leave()

    def display_status(self, output):
        self.window.move(3, 0)
        self.window.clrtoeol()
        if output:
            self.info.line_add("%d lines to display" % len(output.content), (3, 0), "top-left", self.window)
            self.info.display()
        else:
            self.info.line_add("Nothing to display", (3, 0), "top-left", self.window)
            self.info.display()
        
    def launch_waiting_thread(self):
        try:
            t = threading.Thread(target=self.wait_display)
            t.start()
        except (KeyboardInterrupt, SystemExit):
            logging.error("Error when launching waiting thread")
            sys.exit()

    @staticmethod
    def catch_wating_thread():
        # joining loading thread
        main_thread = threading.currentThread()
        for t in threading.enumerate():
            if t is not main_thread:
                t.join()

    def wait_display(self):
        self.window.refresh()

    def set_display_body(self, output, cap):
        if not self.body:
            self.body = output.display(self.window, self.info, output.content, cap)
        else:
            if output.display == OriginFile:
                if not isinstance(self.body, OriginFile): 
                    self.buffer_body.append(self.body)
                    self.body = output.display(self.window, self.info, output.content, cap, output.highlighted_line)
            elif output.display == LogFrequency:
                if not isinstance(self.body, LogFrequency): 
                    self.buffer_body.append(self.body)
                    self.body = output.display(self.window, self.info, output.content, cap, None, output.fmax)
            elif output.display == LogHistory :
                if not isinstance(self.body, LogHistory): 
                    self.buffer_body.append(self.body)
                    self.body = output.display(self.window, self.info, output.content, cap)
            else:
                logging.error("Unknown output display")
                logging.error(output.display)
                sys.exit(0)
        self.body.show_cursor()
        self.body.refresh_pad()

    def start_on_menu(self):
        self.menu.current_field.show_cursor()
        # wait for user input
        c = self.window.getch()
        return self.menu.action(c)

    def go_back(self, output):
        if len(self.buffer_body) >= 1:
            self.body.clear_current_page()
            self.body = self.buffer_body.pop()
            output.display = self.body.__class__
        else:
            output = None
            self.body = None
        return output

    def display_basics(self):
        self.menu.display()
        self.info.display()
        self.window.refresh()

    def leave(self, normalized_logs=None, num_chunks=None):
        if normalized_logs:
            # set normalized blocks to target to
            # release loading thread
            normalized_logs['current_chunk'] = num_chunks
	    self.catch_wating_thread()
        # Set everything back to normal
        self.window.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.endwin()


class Output:
    def __init__(self, display):
        #which body is used to display info
        self.display = display
        self.content = []
        self.highlighted_line = None
        self.fmax = None

    def fill_content_from_strings(self, messages):
        if not self.content:
            for i, m in enumerate(messages):
                self.content.append(Line(m, (i, 0), "top-left"))
        return self

    def set_highlighted_line(self, log=None):
        self.highlighted_line = log
        return self

    def set_max_frequency(self, fmax=None):
        self.fmax = fmax
        return self


class Request:
    def __init__(self, field=None, body=None, message=None, line_number=None, num_lines_max=None, operation=None):
        self.field = field
        self.body = body
        self.message = message
        self.line_number = line_number
        self.num_lines_max = num_lines_max
        self.operation = operation


class Information:
    def __init__(self):
        self.lines = []
        version = "Pyjeet version 1.0"
        helpm = str(datetime.now()).split('.')[0]
        self.lines.append(Line(version, (0, 0), "top-left"))
        self.lines.append(Line(helpm, (0, len(helpm)), "top-right"))

    def line_add(self, text, coord, origin, window):
        # replace line if already line at the same position
        for i, line in enumerate(self.lines):
            if line.position == coord:
                self.lines[i] = Line(text, coord, origin, window)
                return
        self.lines.append(Line(text, coord, origin, window))

    def remove_last(self):
        self.lines.pop()

    def display(self):
        for line in self.lines:
            line.display()


class Line:
    #the attached window is defined in a second pass
    def __init__(self, text, position, origin, window=None):
        self.text = text
        self.position = position
        self.origin = origin
        self.window = window

    @property
    def pos_from_top_left(self):
        if self.origin == "top-left":
            return [self.position[0], self.position[1]]
        else:
            # window dimensions
            (y, x) = self.window.getmaxyx()
            if self.origin == "top-right":
                return [self.position[0], x - self.position[1]]
            elif self.origin == "bottom-left":
                return [y - self.position[0], self.position[1]]
            elif self.origin == "bottom-right":
                return [y - self.position[0], x - self.position[1]]
            else:
                raise ValueError("Invalid origin argument")

    def display(self):
        if self.window:
            try:
                if self.origin == "top-left":
                    self.window.addstr(self.position[0], self.position[1], self.text)
                else:
                    # window dimensions
                    (y, x) = self.window.getmaxyx()
                    if self.origin == "top-right":
                        self.window.addstr(self.position[0], x - self.position[1], self.text)
                    elif self.origin == "bottom-left":
                        self.window.addstr(y - self.position[0], self.position[1], self.text)
                    elif self.origin == "bottom-right":
                        self.window.addstr(y - self.position[0], x - self.position[1], self.text)
                    else:
                        raise ValueError("Invalid origin argument")

            except curses.error:
                return
        else:
            return


class Menu:
    def __init__(self):
        self.fields = []
        self.count = 0

        self.actions = \
            {
                0x1b: self._KEY_ESCAPE,
                curses.KEY_UP: self._KEY_UP,
                curses.KEY_DOWN: self._KEY_DOWN,
                curses.KEY_LEFT: self._KEY_LEFT,
                curses.KEY_RIGHT: self._KEY_RIGHT,

                0x7f: self._KEY_BACKSPACE,
                0x8: self._KEY_BACKSPACE,
                curses.KEY_BACKSPACE: self._KEY_BACKSPACE,

                0xa: self._KEY_ENTER,
                curses.KEY_ENTER: self._KEY_ENTER,
            }

    def add_field(self, field):
        self.fields.append(field)

    def display(self):
        for f in self.fields:
            f.line.display()

    def down(self):
        if self.current_field.input == "":
            self.count += 1

    def up(self):
        if self.current_field.input == "":
            self.count -= 1

    @property
    def current_field(self):
        return self.fields[self.count % len(self.fields)]

    def _KEY_DOWN(self):
        self.down()
        self.current_field.show_cursor()
        return None

    def _KEY_UP(self):
        self.up()
        self.current_field.show_cursor()
        return None

    def _KEY_LEFT(self):
        self.current_field.left()
        self.current_field.show_cursor()
        return None

    def _KEY_RIGHT(self):
        self.current_field.right()
        self.current_field.show_cursor()
        return None

    @staticmethod
    def _KEY_ESCAPE():
        logging.info("User quit application pressing ESC")
        sys.exit(0)

    def _KEY_BACKSPACE(self):
        self.current_field.delete_char()
        self.current_field.show_cursor()
        return None

    def _KEY_ENTER(self):
        return self.current_field.post_Request()

    def action(self, input):
        if input in self.actions:
            return self.actions[input]()
        elif input in range(32, 256):
            self.current_field.insert_char(input)
            self.current_field.show_cursor()
            return None


class Field:
    def __init__(self, line, length, name):
        self.line = line
        self.max_input_length = length
        self.window = line.window
        self.left_limit = line.pos_from_top_left[1] + len(line.text) + 1
        self.pos = [line.pos_from_top_left[0], self.left_limit]
        self.name = name

    @property
    def right_limit(self):
        return self.left_limit + len(self.input) #self.max_input_length

    @property
    def input(self):
        return self.window.instr(self.pos[0], self.left_limit).rstrip()

    def show_cursor(self):
        self.window.move(*self.pos)

    def right(self, check=True):
        if self.pos[1] < self.right_limit and check:
            self.pos[1] += 1
        elif not check:
            self.pos[1] += 1

    def left(self):
        if self.pos[1] > self.left_limit:
            self.pos[1] -= 1

    def insert_char(self, c):
        #insert character, move cursor
        if self.pos[1] - self.left_limit < self.max_input_length:
            self.window.insch(self.pos[0], self.pos[1], c)
            self.right(False)

    def delete_char(self):
        if len(self.input) >= 1 and self.pos[1] > self.left_limit:
            # Delete previous character
            self.window.delch(self.pos[0], self.pos[1] - 1)
            self.left()

    def post_Request(self):
        return Request(self, None, self.input)


class Body:
    __metaclass__ = ABCMeta

    def __init__(self, window, info, output, cap, highlight=None):
        self.window = window
        # cap the number of lines in output to 10000
        self.output = output[:cap]
         # Terminal dimensions
        (self.Y, self.X) = window.getmaxyx()
        # Portion of terminal used for display
        self.body_h = (2 * self.Y)/3
        self.top_margin = 5
        # Information object
        self.info = info
        # Distance of info from bottom
        self.info_y = 8
        # position in the body
        self.pos = None
        #Create pad at the right size
        self.num_lines = len(self.output)
        col_max = 1000
        self.pad = curses.newpad(self.num_lines, col_max)
        # pages
        self.num_full_pages = self.num_lines / self.body_h
        self.remaining_lines = self.num_lines % self.body_h
        self.page_counter = 0
        #Fill the pad with the output
        self.fill_pad()
        # clear previous page
        self.clear_current_page()
        self.window.refresh()
        # number of the line to be highlighted if any
        self.highlight = highlight

    def clear_current_page(self):
        for y in range(self.top_margin, self.top_margin + self.body_h + 1):
            self.window.move(y, 0)
            #delete from cursor to end of line
            self.window.clrtoeol()
        self.window.move(self.top_margin, 0)

    def fill_pad(self):
        for line in self.output:
            line.window = self.pad
            line.display()

    def show_cursor(self):
        self.window.move(*self.pos)

    @property
    #distance from top of input pad
    def top(self):
        if self.remaining_lines == 0:
            return (self.page_counter % self.num_full_pages) * self.body_h
        else:
            return (self.page_counter % (self.num_full_pages + 1)) * self.body_h

    @abstractmethod
    def action(self, c):
        '''
        Define behaviour when a pressed key is given as a parameter
        '''
        pass

    def refresh_pad(self):
        self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)

    def right(self, c):
        offset = 0
        try:
            while 42:
                if c == curses.KEY_RIGHT: 
                    offset += 100
                elif c == curses.KEY_LEFT:
                    offset = max(0, offset - 100)
                else:
                    return
                self.pad.refresh(self.top, offset, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
                # wait for user input
                c = self.window.getch()
        except curses.error:
            return


class LogHistory(Body):
    def __init__(self, window, info, output, cap):
        Body.__init__(self, window, info, output, cap)
        #  Displays first page
        self.display_first_page()

    def display_first_page(self):
        #user info
        (y, x) = self.window.getmaxyx()
        self.window.move(y - self.info_y, 0)
        self.window.clrtoeol()
        info_line = "* %d more lines - press the space bar to display more *" % max((self.num_lines - self.body_h), 0)
        self.info.line_add(info_line, (self.info_y, 0), "bottom-left", self.window)
        self.info.display()
        # pad for log lines
        self.pad.chgat(0, 0, curses.A_REVERSE)
        self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
        # Put cursor on the first line
        self.pos = [self.top_margin, 0]
        self.show_cursor()

    def up(self):
        try:
            if self.pos[0] > self.top_margin:
                #set current line to normal
                self.pad.chgat(self.top + self.pos[0] - self.top_margin, 0, curses.A_NORMAL)
                # move cursor
                self.pos[0] -= 1
                self.show_cursor()
                # highlight next line & refresh
                self.pad.chgat(self.top + self.pos[0] - self.top_margin, 0, curses.A_REVERSE)
                self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
            else:
                pass
        except curses.error:
            return

    def down(self):
        try:
            #if on the last page not fully filled
            if self.remaining_lines != 0 and self.page_counter % (self.num_full_pages + 1) == self.num_full_pages:
                if self.pos[0] < self.remaining_lines + self.top_margin - 1:
                    #unhighlight current line, move cursor, and highlight next line
                    self.pad.chgat(self.top + self.pos[0] - self.top_margin, 0, curses.A_NORMAL)
                    self.pos[0] += 1
                    self.show_cursor()
                    self.pad.chgat(self.top + self.pos[0] - self.top_margin, 0, curses.A_REVERSE)
                    self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
                else:
                    pass
            elif self.pos[0] < self.body_h + self.top_margin - 1:
                self.pad.chgat(self.top + self.pos[0] - self.top_margin, 0, curses.A_NORMAL)
                self.pos[0] += 1
                self.show_cursor()
                self.pad.chgat(self.top + self.pos[0] - self.top_margin, 0, curses.A_REVERSE)
                self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
                return
            else:
                pass
        except curses.error:
            return

    def move_page(self, offset):
        try:
            # unhighlight current line
            self.pad.chgat(self.top + self.pos[0] - self.top_margin, 0, curses.A_NORMAL)
            self.page_counter += offset
            # cleat current page
            self.clear_current_page()
            self.window.refresh()
            # highlight first line of next page
            self.pad.chgat(self.top, 0, curses.A_REVERSE)
            self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
            # Put cursor on the first line
            self.pos = [self.top_margin, 0]
            self.show_cursor()
             # update user info
            if self.remaining_lines != 0 and self.page_counter % (self.num_full_pages + 1) == self.num_full_pages:
                info_line = "* Press the space bar to display the first lines again *"
            else:
                info_line = "* %d more lines - press the space bar to display more *" \
                    % (self.num_lines - self.top - self.body_h)
            (y, x) = self.window.getmaxyx()
            self.window.move(y - self.info_y, 0)
            self.window.clrtoeol()
            self.info.line_add(info_line, (self.info_y, 0), "bottom-left", self.window)
            self.info.display()
        except curses.error:
            return

    def post_Request(self, operation):
        #get args for linked content
        input_line = self.pad.instr(self.top + self.pos[0] - self.top_margin, 0)
        return Request(None, self, input_line, self.top + self.pos[0] - self.top_margin, None, operation)

    def action(self, c):
        #space bar is hit
        if c == 0x20:
            self.move_page(1)
        elif c == curses.KEY_DOWN:
            self.down()
        elif c == curses.KEY_UP:
            self.up()
        elif c == curses.KEY_RIGHT or c == curses.KEY_LEFT:
            self.right(c)
        # Find linked content on enter key from origin file
        elif c == 0xa or c == curses.KEY_ENTER:
            return self.post_Request("origin")
        # Find frequency of logs accross files
        elif c == 0x66:
            self.window.move(2, 0)
            self.window.clrtoeol()
            return self.post_Request("frequency")
        # go back on delete key
        elif c in [0x7f, 0x8, curses.KEY_BACKSPACE]:
            self.move_page(-1)
        else:
            return


class OriginFile(Body):
    def __init__(self, window, info, output, cap, highlight):
        Body.__init__(self, window, info, output, cap, highlight)
        #  Displays first page
        self.display_original_page()

    def display_original_page(self):
        # highlight the given line
        if self.highlight:
            self.pad.chgat(self.highlight, 0, curses.A_REVERSE)
        else:
            raise ValueError("Output should have an highlighted line for OriginFile display\n")
        # get counter to the right page
        self.page_counter = self.highlight / self.body_h
        # user info
        if self.remaining_lines != 0 and self.page_counter % (self.num_full_pages + 1) == self.num_full_pages:
            info_line = "* Press the space bar to display the first lines of the origin file *"
        else:
            info_line = "* %d more lines till end of origin file - press the space bar to display more *" \
                % (self.num_lines - self.top - self.body_h)
        (y, x) = self.window.getmaxyx()
        self.window.move(y - self.info_y, 0)
        self.window.clrtoeol()
        self.info.line_add(info_line, (self.info_y, 0), "bottom-left", self.window)
        self.info.display()
        # pad for log lines
        self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
        # Put cursor on the first line
        self.pos = [self.top_margin, 0]
        self.show_cursor()

    def action(self, c):
        #space bar is hit
        if c == 0x20:
            self.move_page(1)
        elif c == curses.KEY_DOWN:
            self.down()
        elif c == curses.KEY_UP:
            self.up()
        # go back on delete key
        elif c in [0x7f, 0x8, curses.KEY_BACKSPACE]:
            self.move_page(-1)
        elif c == curses.KEY_RIGHT or c == curses.KEY_LEFT:
            self.right(c)
        else:
            return

    def move_page(self, offset):
        try:
            self.page_counter += offset
            # cleat current page
            self.clear_current_page()
            self.window.refresh()
            # highlight first line of next page
            self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
            # Put cursor on the first line
            self.pos = [self.top_margin, 0]
            self.show_cursor()
             # update user info
            if self.remaining_lines != 0 and self.page_counter % (self.num_full_pages + 1) == self.num_full_pages:
                info_line = "* Press the space bar to display the first lines again *"
            else:
                info_line = "* %d more lines - press the space bar to display more *" \
                    % (self.num_lines - self.top - self.body_h)
            (y, x) = self.window.getmaxyx()
            self.window.move(y - self.info_y, 0)
            self.window.clrtoeol()
            self.info.line_add(info_line, (self.info_y, 0), "bottom-left", self.window)
            self.info.display()
        except curses.error:
            return

    def up(self):
        try:
            if self.pos[0] > self.top_margin:
                # move cursor
                self.pos[0] -= 1
                self.show_cursor()
                self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
            else:
                pass
        except curses.error:
            return

    def down(self):
        try:
            #if on the last page not fully filled
            if self.remaining_lines != 0 and self.page_counter % (self.num_full_pages + 1) == self.num_full_pages:
                if self.pos[0] < self.remaining_lines + self.top_margin - 1:
                    #unhighlight current line, move cursor, and highlight next line
                    self.pos[0] += 1
                    self.show_cursor()
                    self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
                else:
                    pass
            elif self.pos[0] < self.body_h + self.top_margin - 1:
                self.pos[0] += 1
                self.show_cursor()
                self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
                return
            else:
                pass
        except curses.error:
            return


class LogFrequency(Body):
    def __init__(self, window, info, output, cap, highlight, fmax):
        Body.__init__(self, window, info, output, cap, highlight)
        self.fmax = fmax
        self.date_left = 1
        self.date_right = 19
        self.after_date = 22
        #  displays first page
        self.display_first_page()

    def display_first_page(self):
        #user info
        (y, x) = self.window.getmaxyx()
        self.window.move(y - self.info_y, 0)
        self.window.clrtoeol()
        info_line = "* %d more lines - press the space bar to display more *" % max((self.num_lines - self.body_h), 0)
        self.info.line_add(info_line, (self.info_y, 0), "bottom-left", self.window)
        self.info.display()
        # pad for log lines
        self.pad.chgat(0, self.date_left, self.date_right, curses.A_REVERSE)
        self.frequency_viz()
        self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
        # put cursor on the first line
        self.pos = [self.top_margin, 0]
        self.show_cursor()

    def frequency_viz(self):
        (y, x) = self.window.getmaxyx()
        # highlight all lines in page according to frequency
        for i in range(self.num_lines):
            frequ = int(self.output[i].text.split(']')[-1])
            if self.fmax != 0:
                ratio = frequ/float(self.fmax)
            else:
                ratio = 1
            length = int(ratio*x)
            self.pad.chgat(i, 22, length, curses.A_REVERSE)

    def up(self):
        try:
            if self.pos[0] > self.top_margin:
                #set current line to normal
                self.pad.chgat(self.top + self.pos[0] - self.top_margin, self.date_left, self.date_right, curses.A_NORMAL)
                # move cursor
                self.pos[0] -= 1
                self.show_cursor()
                # highlight next line & refresh
                self.pad.chgat(self.top + self.pos[0] - self.top_margin, self.date_left, self.date_right, curses.A_REVERSE)
                self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
            else:
                pass
        except curses.error:
            return

    def down(self):
        try:
            #if on the last page not fully filled
            if self.remaining_lines != 0 and self.page_counter % (self.num_full_pages + 1) == self.num_full_pages:
                if self.pos[0] < self.remaining_lines + self.top_margin - 1:
                    #unhighlight current line, move cursor, and highlight next line
                    self.pad.chgat(self.top + self.pos[0] - self.top_margin, self.date_left, self.date_right, curses.A_NORMAL)
                    self.pos[0] += 1
                    self.show_cursor()
                    self.pad.chgat(self.top + self.pos[0] - self.top_margin, self.date_left, self.date_right, curses.A_REVERSE)
                    self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
                else:
                    pass
            elif self.pos[0] < self.body_h + self.top_margin - 1:
                self.pad.chgat(self.top + self.pos[0] - self.top_margin, self.date_left, self.date_right, curses.A_NORMAL)
                self.pos[0] += 1
                self.show_cursor()
                self.pad.chgat(self.top + self.pos[0] - self.top_margin, self.date_left, self.date_right, curses.A_REVERSE)
                self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
                return
            else:
                pass
        except curses.error:
            return

    def move_page(self, offset):
        try:
            # unhighlight current line
            self.pad.chgat(self.top + self.pos[0] - self.top_margin, self.date_left, self.date_right, curses.A_NORMAL)
            self.page_counter += offset
            # cleat current page
            self.clear_current_page()
            self.window.refresh()
            # highlight first line of next page
            self.pad.chgat(self.top, self.date_left, self.date_right, curses.A_REVERSE)
            self.pad.refresh(self.top, 0, self.top_margin, 0, self.body_h + self.top_margin - 1, self.X - 1)
            # put cursor on the first line
            self.pos = [self.top_margin, 0]
            self.show_cursor()
             # update user info
            if self.remaining_lines != 0 and self.page_counter % (self.num_full_pages + 1) == self.num_full_pages:
                info_line = "* press the space bar to display the first lines again *"
            else:
                info_line = "* %d more lines - press the space bar to display more *" \
                    % (self.num_lines - self.top - self.body_h)
            (y, x) = self.window.getmaxyx()
            self.window.move(y - self.info_y, 0)
            self.window.clrtoeol()
            self.info.line_add(info_line, (self.info_y, 0), "bottom-left", self.window)
            self.info.display()
        except curses.error:
            return

    def get_context(self):
        #get args for linked content
        input_line = self.pad.instr(self.top + self.pos[0] - self.top_margin, 0)
        input_line = input_line.split('[')[-1].split(']')[0]
        return Request(None, self, input_line, self.top + self.pos[0] - self.top_margin, None, "context")

    def action(self, c):
        #space bar is hit
        if c == 0x20:
            self.move_page(1)
        elif c == curses.KEY_DOWN:
            self.down()
        elif c == curses.KEY_UP:
            self.up()
        # find content at time stamp on Enter Key
        elif c == 0xa or c == curses.KEY_ENTER:
            return self.get_context()
        # go back on delete key
        elif c in [0x7f, 0x8, curses.KEY_BACKSPACE]:
            self.move_page(-1)
        elif c == curses.KEY_RIGHT or c == curses.KEY_LEFT:
            self.right(c)
        else:
            return

