from tkinter import (
    BooleanVar,
    StringVar,
    Text,
    Tk,
    ttk,
    filedialog,
    messagebox,
)
import tkinter
import base64
import socket
from typing import List, Tuple, Union
import pynetstring
import re
import traceback
from tkinter.constants import TOP


class MemeGui:
    """Ugly GUI for MTP client app (I'm a frontend disaster)"""

    def __init__(self, client: "MTPClient"):
        self.client = client

    def _build(self) -> None:
        """Builds the GUI"""
        # main window
        self.root = Tk()
        self.root.geometry("900x400")
        self.root.title("MTP Client")

        self.ip = StringVar()
        self.port = StringVar()
        self.name = StringVar()
        self.password = StringVar()
        self.nsfw = BooleanVar()

        # frames
        self.main_frame = ttk.Frame(self.root).pack(
            fill=tkinter.BOTH, expand=True
        )
        entry_frame = ttk.Frame(self.main_frame)

        # some frontend I barely understand
        address_label = ttk.Label(entry_frame, text="IP Address: ").grid(
            column=0, row=0, sticky="nw"
        )
        address_field = ttk.Entry(entry_frame, textvariable=self.ip).grid(
            column=1, row=0, sticky="nw"
        )

        name_label = ttk.Label(entry_frame, text="Name: ").grid(
            column=0, row=1
        )
        name_field = ttk.Entry(entry_frame, textvariable=self.name).grid(
            column=1, row=1
        )

        port_label = ttk.Label(entry_frame, text="Port: ").grid(
            column=2, row=0
        )
        port_field = ttk.Entry(entry_frame, textvariable=self.port).grid(
            column=3, row=0
        )

        password_label = ttk.Label(entry_frame, text="Password: ").grid(
            column=2, row=1
        )
        password_field = ttk.Entry(
            entry_frame, textvariable=self.password
        ).grid(column=3, row=1)
        entry_frame.pack()

        nsfw_checkbox = ttk.Checkbutton(
            self.main_frame, text="NSFW", variable=self.nsfw
        ).pack()

        self.description_field = Text(self.main_frame, height=16, width=100)
        self.description_field.pack()

        self.meme_picker = ttk.Button(
            self.main_frame, text="Pick a MEME", command=self._pick_meme
        ).pack()

        submit_button = ttk.Button(
            self.main_frame,
            text="Send MEME",
            command=self._prepare_and_send_meme,
        ).pack()

        self.root.mainloop()
        return

    def _pick_meme(self) -> None:
        """Creates a file picker window and saves chosen file"""
        file_path = filedialog.askopenfilename()
        pattern = re.compile("^.+\.png$|^.+\.jpeg$")
        if re.match(pattern, file_path):
            self.meme_path = file_path
        else:
            messagebox.showerror(
                "Error",
                "File containing meme must be either in PNG or JPEG format",
            )

    def _prepare_and_send_meme(self) -> None:
        """Typecheck all fields, pass the data to the"""
        ip: str = ""
        port: int = 0
        name: str = self.name.get()
        password: str = self.password.get()
        is_nsfw: bool = self.nsfw.get()
        description: str = self.description_field.get(1.0, "end-1c")
        meme: str = ""

        # IP address format check
        try:
            # checking for the 4 number places
            arr = self.ip.get().split(".")
            if len(arr) != 4:
                trace = traceback.format_exc()
                raise Exception(
                    "IP Address must contain exactly 4 octets" + f"\n{trace}"
                )

            # checking if the contents are numbers && from the 0-255 range
            for octet in arr:
                octet = int(octet)
                if octet < 0 or octet > 255:
                    trace = traceback.format_exc()
                    raise Exception(
                        "IP Address octects must come from the range of 0-255"
                        + f"\n{trace}"
                    )
                ip += str(octet) + "."

            # remove the trailing . (dot)
            ip = ip[:-1]
        except Exception as e:
            trace = traceback.format_exc()
            print(str(e) + f"\n{trace}")
            messagebox.showerror(
                "IP Address Format Error",
                "IP Address format is incorrect, please use the standard IP format!",
            )
            return

        # port type check
        try:
            port = int(self.port.get())
        except Exception as e:
            trace = traceback.format_exc()
            print(str(e) + f"\n{trace}")
            messagebox.showerror(
                "Port Format Error",
                "Port format is incorrect, please use integer values!",
            )
            return

        # name check
        if name == "":
            messagebox.showerror(
                "Name Error",
                "Name field cannot be empty, please fill in your name!",
            )
            return

        # password check
        if password == "":
            messagebox.showerror(
                "Password Error",
                "Password field cannot be empty, please fill in your password!",
            )
            return

        # creation of base64 form of meme
        try:
            meme = base64.b64encode(open(self.meme_path, "rb").read()).decode(
                "ascii"
            )
        except Exception as e:
            trace = traceback.format_exc()
            print(str(e) + f"\n{trace}")
            messagebox.showerror(
                "Meme File Error",
                "Meme file was not specified, please specify it and try again!",
            )
            return

        messagebox.showinfo(
            "Starting",
            "Meme is being processed and sent! Please wait, as you are going to be informed based on the result",
        )
        self.client.send_meme(
            ip, port, name, password, is_nsfw, description, meme
        )

    def error(self, message: str) -> None:
        """Creates an error window"""
        messagebox.showerror("Error", message + "!")


class SocketHandler:
    """Custom interface class - handles all communication inbetween sockets"""

    TIMED_OUT_TIMER = 10.0  # seconds
    TIMED_OUT_MESSAGE = (
        f"Timed out: server did not respond in time (>{TIMED_OUT_TIMER}s)"
    )

    def __init__(self, socket: socket.socket):
        self.socket = socket
        self.stack: List[str] = []
        self.decoder: pynetstring.Decoder = pynetstring.Decoder()
        self.socket.settimeout(self.TIMED_OUT_TIMER)

    def _send(self, data: str) -> None:
        """Sends data in netstrings encoding"""
        encoded_data = pynetstring.encode(data)
        self.socket.sendall(encoded_data)

    def _recv_into_stack(self) -> None:
        """
        Listens for data and applies netstring decoding, appends captured
        responses to the stack
        """

        while True:
            try:
                capture = self.socket.recv(4096)
            except TimeoutError as e:
                raise TimeoutError(self.TIMED_OUT_MESSAGE) from e
            temp = self.decoder.feed(capture)
            if temp != []:
                # casting from byte string to "normal" string
                for x in temp:
                    s = x.decode("utf-8")
                    if s[0:2] == "E ":
                        raise Exception(
                            "Server raised an error, halting all processes"
                        )
                    self.stack.append(s)
                break

    def _await_response(
        self,
        expected: str,
        exception: str = "Server responded inadequately",
        optional: bool = False,
    ) -> Union[str, List[str]]:
        """
        Looks up the stack for expected response the protocol, returns data
        if they are expected (\"<>\" notation in expected str)
        """
        if self.stack == []:
            self._recv_into_stack()
        response = self.stack.pop(0)
        data = []

        """
        if the response should contain any kind of non-static information,
        treat the expected string as a regex and save it to
        """
        if "<>" in expected:
            # check if the response is valid in the first place
            pattern = re.compile("^" + expected.replace("<>", ".+") + "$")
            try:
                assert re.match(pattern, response), exception
            except AssertionError as e:
                if not optional:
                    raise AssertionError(exception) from e
                else:
                    self.stack.insert(0, response)
                    return

            # find the indexes of placeholders in the expected response
            indexes = [
                substr.start() for substr in re.finditer("<>", expected)
            ]

            """
            go to placeholder's starting index and check what character should
            be right after the placeholder, extract that index and use it
            as the ending index of the data in response

            (this may be overkill, but would solve the problem,
            if the protocol expanded and would pass, for example,
            multiple tokens via one server response - not each one
            in a separate netstring)

            fails if the placeholder is followed by a character that
            also occurs inside the data - however, this would be
            an inconsistency on the side of the protocol, not
            the algorithm
            """
            for i in indexes:
                if len(expected) <= i + 2:
                    data.append(response[i:])
                else:
                    stop_char = expected[i + 2]
                    stop_index = response.index(stop_char, i)
                    data.append(response[i:stop_index])
            return data[0] if len(indexes) == 1 else data
        else:
            try:
                assert response == expected, exception
            except AssertionError as e:
                if not optional:
                    raise AssertionError(exception) from e
                else:
                    self.stack.insert(0, response)


class MTPClient:
    """
    Client for the usage of MTP (MTP V:1.0)
    ---------------------------
    GUI    (standalone usage)      -> main()\n
    NO GUI (third-party usage)     -> send_memes(*args)
    """

    def _build_gui(self) -> None:
        """Builds the application GUI"""
        self.gui = MemeGui(self)
        self.gui._build()

    def send_meme(
        self,
        ip: str,
        port: int,
        name: str,
        password: str,
        is_nsfw: bool,
        description: str,
        meme: str,
    ) -> None:
        """Sends memes to the target location via MTP"""
        self.ip = ip
        self.port = port
        self.name = name
        self.password = password
        self.is_nsfw = is_nsfw
        self.description = description
        self.meme = meme

        # handle any exception during runtime + case of tcp connection failure
        try:
            # connect via tcp to the server
            main_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            main_socket.connect((self.ip, self.port))

            # initialize main socket handler - custom interface for socket communication
            main_channel = SocketHandler(main_socket)

            # 3 main stages of the protocol - init, transport, end
            token_a, data_port = self._initialize_connection(main_channel)
            token_b, data_len = self._transport_data(token_a, data_port)
            self._end_connection(main_channel, token_b, data_len)
            messagebox.showinfo(
                "Success",
                "You've successfully sent a meme to the server at {}:{}!".format(
                    self.ip, self.port
                ),
            )
            return
        except socket.error as e:
            print(str(traceback.format_exc()))
            e_msg = "Could not set up a connection / Connection disrupted"
            print(e_msg)
            self.gui.error(e_msg)
        except Exception as e:
            print(str(traceback.format_exc()))
            main_channel._send(f"E {str(e)}")
            self.gui.error(str(e))
        finally:
            main_socket.close()
        self.gui.error(
            "Your meme wasn't successfully delivered, check whether the host is up and try again later"
        )

    def _initialize_connection(
        self, channel: SocketHandler
    ) -> Tuple[str, int]:
        """Represents the 1st stage of MTP"""
        # verify if both nodes use the same version of MTP
        channel._send("C MTP V:1.0")
        channel._await_response(
            "S MTP V:1.0",
            "Server did not respond correctly to the version challenge (init stage)",
        )

        # pass a nickname to send memes under
        channel._send(f"C {self.name}")

        # recieve token and data channel port
        token = channel._await_response(
            "S <>", "Token was not recieved successfully (init stage)"
        )
        data_port = channel._await_response(
            "S <>", "Data port was not recieved successfully (init stage)"
        )

        return (token, int(data_port))

    def _transport_data(self, token: str, data_port: int) -> str:
        """Represents the 2nd stage of MTP"""
        # connect to the data channel
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.connect((self.ip, data_port))
        data_channel = SocketHandler(data_socket)

        # greet the server with our nick :)
        data_channel._send(f"C {self.name}")

        # recieve confirmation token and data type, verify token match
        recv_token = data_channel._await_response(
            "S <>",
            "Couldn't start the data transport due to server's unexpected behaviour  (transport stage)",
        )
        assert (
            recv_token == token
        ), "Pre-data transport token mismatch (transport stage)"

        # TRANSPORT LOOP
        # capture total length of data sent to server
        data_len_sum = 0
        while True:
            current_data_len = 0

            # identify target data and check if it can be accessed
            requested_data_type = data_channel._await_response(
                "S REQ:<>",
                "Expected data type was not recieved successfully (transport stage)",
            )
            assert requested_data_type in [
                "meme",
                "description",
                "isNSFW",
                "password",
            ], f"Unknown data type requested: {requested_data_type} - use meme, description, isNSFW or password  (transport stage)"

            # send requested data
            if requested_data_type == "meme":
                data_channel._send(f"C {self.meme}")
                current_data_len = len(self.meme)
            elif requested_data_type == "description":
                data_channel._send(f"C {self.description}")
                current_data_len = len(self.description)
            elif requested_data_type == "isNSFW":
                val = "true" if self.is_nsfw else "false"
                data_channel._send(f"C {val}")
                current_data_len = len(val)
            else:
                data_channel._send(f"C {self.password}")
                current_data_len = len(self.password)

            # suppose that data corruption doesn't occur and so if the lengths match - data was transported successfully
            recv_data_len = data_channel._await_response(
                "S ACK:<>",
                "Data length of the sent data was not recieved successfully (transport stage)",
            )
            assert (
                int(recv_data_len) == current_data_len
            ), "Recieved data length doesn't match the sent data length (transport stage)"
            data_len_sum += current_data_len

            # attempt to recieve a token and end communication on this channel
            token = data_channel._await_response(
                "S END:<>",
                exception="Token was not recieved successfully (transport stage)",
                optional=True,
            )
            if token:
                data_socket.close()
                return (token, data_len_sum)

    def _end_connection(
        self, main_channel: SocketHandler, token: str, data_len: int
    ) -> None:
        """Represents the 3rd stage of MTP"""
        # check if total length of data recieved by server matches the sent
        recv_data_len = main_channel._await_response(
            "S <>",
            "Total length of data was not recieved successfully (end stage)",
        )
        assert (
            int(recv_data_len) == data_len
        ), "Total length of data recieved by server doesn't match the total length of data sent by client (end stage)"

        # identify with the token recieved at the end of the data transport
        main_channel._send(f"C {token}")

        # check for ack of the end of the communication
        main_channel._await_response(
            "S ACK", "Server did not acknowledge the end of communication"
        )

    def main(self) -> None:
        """Entry point of the MTP client"""
        self._build_gui()


if __name__ == "__main__":
    client = MTPClient()
    client.main()
