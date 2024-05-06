https://cse312theprogrammers.me/

The newest version of the app is running from the master branch. To run locally, all mentions of the domain name must be changed to localhost or localhost:8080

Bonus Feature: Content Filter
The site has a filter so that if a username is submitted for registration that contains a banned word, the user will be alerted and the account will not be registered
In the same vein, sending a message that contains a banned word will alert the user and the message will not be submitted and shown to other users
We have added a list of banned phrases in a seperate file that you can use for testing.
Testing:
1. Navigate to the public deployment (cse312theprogrammers.me)
2. Attempt to register with an account that contains the banned phrase "13 seconds"
3. Verify that the page returns to the homepage and that an error message is displayed below the registration form
4. Register with an account that contains "dingus", but with several capital letters (Ex. DiNgUs)
5. Verify that the page returns to the homepage and that the same error message is displayed
6. Register with an account that does not contain the word
7. Verify that the page shows a successful message and login using the inputted username and password, verifying that the username displays on the page
8. Go to any of the 3 chatroom pages shown on the home screen
9. Attempt to send multiple messages in the same vein as the registration and verify that the site displays a message saying the message was not sent for containing a banned word and that the message is not shown in the chatroom.
10. Use a second browser to confirm that the message will not be displayed to other users
