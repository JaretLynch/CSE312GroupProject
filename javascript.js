

$(document).ready(function() {

    console.log("Document: ", document)
    var name = $('#Name').text();
    // Function to establish WebSocket connection
    var username = "{{ data.username }}";

    function connectWebSocket(dest) {
        
        var usernameEntry = document.getElementById("usernameEntry");

        // Extract the username from the paragraph's text content
        var username = usernameEntry.textContent.replace("Logged in as: ", "");

        console.log("Username:", username)
        console.log("calling connect websocket")
        socket = io('wwss://cse312theprogrammers.me', 
        { transports: ['websocket'], 
        upgrade: false, 
        query: {
            username: username,
            dest: dest,
            room:name
            }
        });
        socket.on('user_joined', function() {
            if (name!=""){

                socket.emit('get_user_list', {'room': name, 'username': username});
            }
        });

        socket.on('user_left', function(){
            if (name!=""){

            socket.emit('get_user_list', {'room': name, 'username': username});
            }
        });

        socket.on('user_list', function(data) {
            var activeUsers = data.user_list;
            console.log("Active users: ", activeUsers)
            $('#userlist').empty();
            activeUsers.forEach(function(user) {
                var userElement = $('<div class="user"></div>');
                // Calculate the duration in minutes and seconds
                var minutes = Math.floor(user[1] / 60);
                var seconds = user[1] % 60;
                // Format the duration string
                var durationString = minutes + " minutes " + seconds + " seconds";
                // Append the username and duration to the user element
                userElement.append('<strong>' + user[0] + '</strong>');
                userElement.append('<span> Active for ' + durationString + '</span>');
                $('#userlist').append(userElement);
            });
        });
        console.log("after calling connect websocket")
    
        // WebSocket event listeners
        socket.on('connect', function() {
            console.log('WebSocket connected');
            // fetchCommentsAndUpdate(name); // Fetch comments after WebSocket connection is established
        });
        // Periodically request updated active users list
        setInterval(function() {
            if (name!=""){
                socket.emit('get_user_list', {room: name});
            }
        }, 1000);

        socket.on('disconnect', function() {
            console.log('WebSocket disconnected');
        });

        $('#send-comment').click(function (event) {
            console.log("sending comment")
            var name = $('#destination').text();
            console.log(name)

            event.preventDefault(); // Prevent the default form submission
            
            // Get the comment content and destination from the input fields
            var content = $('#comment').val();
            var destination = $('#destination').val();
            console.log(destination)
            // Emit a websocket event for comment creation
            socket.emit('create_comment', { "comment": content, "destination": destination });

            // Fetch comments and update comments section immediately after sending a new comment
            $('#comment').val(''); // Clear the input field
            // fetchCommentsAndUpdate(destination);
        })

        socket.on('Comment_Broadcasted', function(comment) {
            console.log("CommentBroadcasted")
            // Extract the username and message from the received data
            commentElement=$('#comments')

            // Update the comments section with the new comment
            commentElement.append('<strong>' + comment.author + '</strong>: ' + comment.content);
            commentElement.append('<br><span class="comment-id"> ID: ' + comment.comment_id + ' </span>');
            commentElement.append('<button class="like-btn" data-comment-id="' + comment.comment_id + '">Like</button>');
            commentElement.append('<span class="likes-count"> Likes: ' + comment.likes + '</span>'+'<br>');

        });
        socket.on('connect_error', function(error) {
            console.error('WebSocket connection error:', error);
        });
        
    }
    // Function to close WebSocket connection
    function disconnectWebSocket() {
        if (socket) {
            socket.close();
            socket = null; // Reset WebSocket variable
        }
    }

    
    // Function to fetch comments and update comments section
    function fetchCommentsAndUpdate(destination) {
        $.get('/get_comments', { destination: destination }, function(data) {
            // Clear existing comments
            $('#comments').empty();

            // Iterate over fetched comments and construct HTML elements
            data.comments.forEach(function(comment) {
                var commentElement = $('<div class="comment"></div>');
                if (comment.profile_pic) {
                    commentElement.append(comment.profile_pic);
                }
                commentElement.append('<strong>' + comment.author + '</strong>: ' + comment.content);
                commentElement.append('<br><span class="comment-id"> ID: ' + comment.comment_id + ' </span>');
                commentElement.append('<button class="like-btn" data-comment-id="' + comment.comment_id + '">Like</button>');
                commentElement.append('<span class="likes-count"> Likes: ' + comment.likes.length + '</span>');

                // Append comment element to comments section
                $('#comments').append(commentElement);
            });
        });
    }
    var dest = $('#Name').text();
    console.log("dest is ")
    console.log(dest)
    if (dest === "Bills" || dest === "Sabres" || dest === "General") {
        connectWebSocket(dest);
    }
    else{
        connectWebSocket("False")
    }
    // Detect page unload or refresh
    window.addEventListener('beforeunload', function(event) {
        // Close the WebSocket connection
        disconnectWebSocket();
    });
});