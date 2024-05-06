
var intervalId;
function welcome(){

    console.log("Welcome")
}
$(document).ready(function() {
    var dest = $('#Name').text();
    console.log("Dest: ", dest)
    console.log("Document: ", document)
    var username = usernameEntry.textContent.replace("Logged in as: ", "");

    // Function to establish WebSocket connection
    function connectWebSocket(dest) {
        var usernameEntry = document.getElementById("usernameEntry");
        var username = usernameEntry.textContent.replace("Logged in as: ", "");
        console.log("Username:", username)
        socket = io('wss://cse312theprogrammers.me/', 
        { transports: ['websocket'], 
        upgrade: false, 
        query: {
            dest: dest,
            username: username
            }
        });
    
        // WebSocket event listeners
        socket.on('connect', function() {
            console.log('WebSocket connected');
            // fetchCommentsAndUpdate(name); // Fetch comments after WebSocket connection is established
        });
    
        socket.on('disconnect', function() {
            console.log('WebSocket disconnected');
        });

        socket.on('user_joined', function() {
            socket.emit('get_user_list', {'room': dest, 'username': username});
            console.log("User joing and destination is ")
            console.log(dest)
        });

        socket.on('user_left', function(){
            socket.emit('get_user_list', {'room': dest, 'username': username});
            console.log("User leaving and destination is ")
            console.log(dest)
        });

        $('#send-comment').click(function (event) {
            console.log("sending comment")
            var name = $('#destination').text();
            console.log(name)

            event.preventDefault(); // Prevent the default form submission
            document.getElementById('messagesent').innerText = ""
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

        // Event listener for like buttons
        $(document).on('click', '.like-btn', function() {
            if (username =="Guest") {
                // Show a popup informing the user to login
                alert('You need to login to use the like feature.');
                return; // Stop further execution
            }
            // Get the comment ID from the data attribute
            var commentId = $(this).data('comment-id');
            socket.emit('like_comment', { "id": commentId, "destination": dest})
        });

        socket.on('Comment_Broadcasted', function() {
            console.log("CommentBroadcasted");
            fetchCommentsAndUpdate(dest)
        });
        socket.on('filter_triggered', function() {
            document.getElementById('messagesent').innerText = "Your comment was not submitted due to containing a banned word."
        });
        socket.on('Comment_Liked', function() {
            console.log("CommentLiked");
            fetchCommentsAndUpdate(dest)
        });
        socket.on('connect_error', function(error) {
            console.error('WebSocket connection error:', error);
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
        function startSocketEmit() {
            intervalId = setInterval(function() {
                if (!document.hidden) {
                    socket.emit('get_user_list', {dest: dest});
                }
            }, 1000);
        }
        function stopSocketEmit() {
            clearInterval(intervalId);
        }
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                stopSocketEmit();
            } else {
                startSocketEmit();
            }
        });
        // Start emitting when the page is initially loaded and visible
        if (!document.hidden) {
            startSocketEmit();
        }
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
    if (dest === "Bills" || dest === "Sabres" || dest === "General") {
        connectWebSocket(dest);
        fetchCommentsAndUpdate(dest);
    }
    else{
        connectWebSocket("False")
    }
    // Detect page unload or refresh
    window.addEventListener('beforeunload', function(event) {
        disconnectWebSocket();
    });
});