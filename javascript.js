function welcome(){
    console.log("I did nothing")
}

$(document).ready(function() {
    console.log("Document: ", document)
    var name = $('#Name').text();
    
    // Establish a websocket connection
    var socket = io('ws://localhost:8080', {transports: ['websocket'], upgrade: false});

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

    // Function to fetch comments and update comments section
    function fetchCommentsAndUpdate(destination) {
        // Emit a websocket event to request comments
        socket.emit('get_comments', { "destination": destination });
    }

    // Receive comments from the server
    socket.on('get_comments', function(data) {
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

    // Fetch comments and update comments section initially
    fetchCommentsAndUpdate(name);

    // Fetch comments and update comments section every 5 seconds
    setInterval(function() {
        fetchCommentsAndUpdate(name);
    }, 5000);

    // Detect page unload or refresh
    window.addEventListener('beforeunload', function(event) {
        // Close the WebSocket connection
        socket.close();
    });
});