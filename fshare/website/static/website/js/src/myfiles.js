
/* Callback when a file has been deleted */
var deleted = function(fid) {
    if (confirm("Are you sure you want to delete this file (permanent)?"))
        $("#file-" + fid).remove();
}

var get_filename = function(el) {
    jQuery.ajax({
        url: $(".name", el).attr("data-href"),
        data: { csrf: $(el).attr("data-csrf") },
        success: function(data) { 
            if (data != "")
                $(".name > a", el).text(data);
        },
    });
}

/* Init links to delete files w/ ajax request on click */
$(document).ready(function() {
    $(".delete-btn").each(function() {
        $(this).click(function() {
            var fid = $(this).attr("data-fid");
            jQuery.ajax( {
                url: $(this).attr("data-href"),
                data: { csrf: $(this).attr("data-csrf") },
                success: function() { deleted(fid); },
            });
        });
    });
    $(".pwd-btn").each(function() {
        $(this).click(function() {
            show_pwd(this);
        });
    });
    $(".link-btn").each(function() {
        $(this).click(function() {
            var key = $(this).parent().parent().attr("data-key");
            var href = "https://" + document.domain + $(this).attr("data-href");
            show_link(href, key);
        });
    });

    $(".file").each(function() {
        get_filename(this);
    });

});

