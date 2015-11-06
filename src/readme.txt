Welcome to this beautiful secure chat.

To run the server using this command:
make -C ./src
./src/chatd $(/labs/tsam15/my_port)

To run the client use this command:
./src/chat localhost $(/labs/tsam15/my_port)

The password is master

--------------------------------------------------------------------------

There are 6 commands supported in this chat, they are:

/help				Lists the commands supported and their functionality
/bye				Cleans up and closes the connection.
/who				Lists the name, IP address, port number and chat
					room the user is currently in of all users available
					on the system.
/list				Lists the names of all available public chat rooms.
/join chatroom		Joins the chatroom, named chatroom a user can only be
					in one chatroom at a time so he is deleted from the previous chatroom.
/user username		User changes his username to username.

--------------------------------------------------------------------------

Questions:

-- 5. Authentication --
Where are the passwords stored? Where are the salt strings stored? Why do
you send the plain text password/hashed password? What are the security
implications of your decision?
> We did not implement this part of the assignment.

-- 6. Private Message --
Logging of private messages: Should private messages be logged? If so,
what should be logged about private messages? What are the consequences
of your decisions?
> We do not think that private messages should be logged because it is
an invasion of privacy and our chatroom is not an evil monster.

--------------------------------------------------------------------------

References:

We worked with Hrönn Róbertsdóttir, Anton Marinó Stefánsson and Sigrún
Þorsteinsdóttir on the assignment.
We also got help from Arnar Gauti Ingason.

We used these codes referenced below and Marcel's code to build the
foundation of the SSL client and SSL server as well as from Gulli (TA).

http://h71000.www7.hp.com/doc/83final/ba554_90007/ch05s03.html
http://h71000.www7.hp.com/doc/83final/ba554_90007/ch05s04.html
