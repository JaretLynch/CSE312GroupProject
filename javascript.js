function welcome(){
    console.log("I did nothing")
}


$(document).ready(function() {
    var name = $('#Name').text();
    // Function to handle comment form submission
    $('#comment-form').submit(function(event) {
        event.preventDefault(); // Prevent the form from submitting normally

        // Get the comment content from the input field
        var content = $('#comment').val();

        // Make an AJAX request to the create_comment endpoint
        $.ajax({
            url: '/create_comment',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ "comment": content,"destination":name }),
            success: function(data) {
                // Display success message
                $('#success-message').text("Comment sent successfully");

                // Clear the comment input field
                $('#comment').val('');

                // Append the new comment to the comments section
                $('#comments').append('<div class="comment"><strong>' + data.author + '</strong>: ' + data.content + '<span class="comment-id">ID: ' + data.comment_id + '</span><button class="like-btn" data-comment-id="' + data.comment_id + '">Like</button><span class="likes-count">Likes: 0</span></div>');
            },
            error: function(xhr, status, error) {
                // Handle error
                console.error("Error:", error);
                // Display error message to the user
                $('#error-message').text("An error occurred while processing your request.");
            }
        });
    });

    // Function to handle like button click
    $(document).on('click', '.like-btn', function() {
        var commentId = $(this).data('comment-id');
        var likesCountSpan = $('.comment[data-comment-id="' + commentId + '"] .likes-count');

        $.post('/like_comment', { comment_id: commentId })
        .done(function(data) {
            // If like is successful, update the likes count
            if (data.likes_count !== undefined) {
                likesCountSpan.text('Likes: ' + data.likes_count);
            } else {
                // Display the error message in the HTML
                $('#error-message').text(data.error);
            }
        })
        .fail(function(xhr) {
            // Handle failed request (e.g., network error)
            if (xhr.status === 400) {
                // Client error, display specific error message
                $('#error-message').text(xhr.responseJSON.error);
            } else {
                // Server error or other unexpected error
                $('#error-message').text("An error occurred while processing your request.");
            }
        });
    });

    // Function to fetch comments and update comments section
    function fetchCommentsAndUpdate(destination) {
        $.get('/get_comments',{destination: destination}, function(data) {
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
    
    // Fetch comments and update comments section initially
    fetchCommentsAndUpdate(name);

    // Fetch comments and update comments section every 5 seconds
    setInterval(fetchCommentsAndUpdate, 5000);
});

function serveChatroom(page){
    fetch('/' + page, {
        method: 'GET'
    })
    .then(response => {
        if (response.ok) {
        } else {
            console.error('Failed to fetch page:', response.statusText);
        }
    })
    .catch(error => {
        console.error('Error fetching page:', error);
    });

}
