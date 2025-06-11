This program was created to work with both Windows and Linux operating systems.
I tested the program with Windows 11 and Ubuntu 20.04, they both work as expected.
The program works with python 3.8.10+

To run the application follow these actions on ubuntu: 
1- Create a virtual enviroment with `python3 -m venv myenv`
2- Activate the virtual enviroment with `source myenv/bin/activate`
3- Install the dependancies using `pip install -r requirements.txt`
4- Run the application with `python3 SecureChat.py`

After entering your name the application will discover any other computers running the same app within your network.
Upon discovery, the online users will be listed. You can choose a user by their index and send messages to them.
Each message recieve, message send and user discovery will cause re renders. This makes the app display everything almost in real time.
The app uses Diffie-Hellman key exchange and DES encryption to safely transport messages. The shared key evolves over time with sent messages, this makes the sniffing attacks almost impossible.
