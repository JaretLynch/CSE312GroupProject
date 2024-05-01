function welcome(){
    console.log("I did nothing")
}

$(document).ready(function() {
    var name = $('#Name').text();
    var username = "{{ data.username }}";
    function connectWebSocket() {
        // Get the paragraph element by its ID
        var usernameEntry = document.getElementById("usernameEntry");

        // Extract the username from the paragraph's text content
        var username = usernameEntry.textContent.replace("Logged in as: ", "");
        console.log("Username:", username)
        const socket = io('wss://localhost', { 
            transports: ['websocket'], 
            upgrade: false,
            query: {
                username: username,
                room: name,
            }
        });
        // WebSocket event listeners
        socket.on('connect', function() {
            console.log('WebSocket connected');
            fetchCommentsAndUpdate(name); // Fetch comments after WebSocket connection is established
        });
    
        socket.on('disconnect', function() {
            console.log('WebSocket disconnected');
        });

        socket.on('user_joined', function() {
            socket.emit('get_user_list', {'room': name, 'username': username});
        });

        socket.on('user_left', function(){
            socket.emit('get_user_list', {'room': name, 'username': username});
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

        $('#send-comment').click(function (event) {
            event.preventDefault(); // Prevent the default form submission
            
            // Get the comment content and destination from the input fields
            var content = $('#comment').val();
            var destination = $('#destination').val();

            // Emit a websocket event for comment creation
            socket.emit('create_comment', { "comment": content, "destination": destination });

            // Fetch comments and update comments section immediately after sending a new comment
            $('#comment').val(''); // Clear the input field
            fetchCommentsAndUpdate(name);
        })
        
    
        // Periodically request updated active users list
        setInterval(function() {
            socket.emit('get_user_list', {room: name});
        }, 1000);
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
    connectWebSocket();
    fetchCommentsAndUpdate(name);

    // Detect page unload or refresh
    window.addEventListener('beforeunload', function(event) {
        disconnectWebSocket();
    });
});