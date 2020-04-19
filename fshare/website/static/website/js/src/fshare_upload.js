Dropzone.autoDiscover = false;

var page_title = document.title;

/* Generate a random key for upload */
var generate_key = function() {
    var key = "";
    var char_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    var len = 20;

    for (var i=0; i < len; i++)
        key += char_set.charAt(Math.floor(Math.random() * char_set.length));

    return key;
}

var ui_generate_key = function() {
        var key = generate_key();
        key = generate_key();
        $("#id_key").val(key);
}

$(document).ready(function () {

    /* Init key generation button */
    $("#gen-key-btn").click(ui_generate_key);

    /* Init Copy button */
    var clip = new Clipboard("#cpy-link-btn");
    clip.on('success', function(e) {
        $(filter).removeClass("hidden");
        $(".text", filter).html("copied!");
        setTimeout(function() { $(filter).addClass("hidden"); }, 1000);
    });

    /* Generate key */
    ui_generate_key();

    var fDropzone = new Dropzone('#upload-form'),
        form = $("#upload-form");

    fDropzone.options.maxFilesize = max_file_size;
    fDropzone.options.uploadMultiple = true;
    fDropzone.options.parallelUploads = 50;

    /*
    fDropzone.options.accept = function (file, done) {
        var size = 0;
        $.get(form.attr('data-size'), function( data ) {
            size = parseInt(data);
            if (file.size <= size) {
                done();
            } else {
                done("There is not enough available space.")
            }
        });
    }
    */

    fDropzone.options.maxFiles = 50;

    var nanobar;
    var options = {
        id : "upload-progression",
        bg: "#8D608C"
    }
    var nanobar =  new Nanobar( options );

    var ref_file = null;
    var err_displayed = false;

    fDropzone.on('addedfile', function (file) {
        error_displayed = false;
        if (ref_file == null)
            ref_file = file;
        if (ref_file != file)
            return;
        nanobar.go(0);
        $(filter).removeClass("hidden");
        $(".text", filter).html("uploading file&nbsp;");
        routine = setInterval(waiting_for_file, 1000);
    }).on('uploadprogress', function(file) {
        if (ref_file != file)
            return;
        nanobar.go(file.upload.progress);
        document.title = "FShare - Uploading " + Math.round(file.upload.progress) + "%";
        if (file.upload.progress == 100) {
            $(".text", filter).html("ciphering file ... please wait&nbsp;");
            $.removeCookie("fileReady");
            clearInterval(routine);
            routine = setInterval(waiting_for_file, 1000);
        }
    }).on('complete', function(file) {
        ref_file = null;
        $(filter).addClass("hidden");
        clearInterval(routine);
        if (file.xhr == undefined)
            return;
        if (file.xhr.response == "ERROR") {
            if (!error_displayed) {
                alert("An error occurred (quota exceeded?)");
                error_displayed = true;
            }
            return;
        }
        document.title = "FShare - Upload completed"
        var href =  file.xhr.response.split("\n")[0];
        var key = $("input#id_key").val();
        if (key == undefined || key == " ")
            key = "";
        show_link(href, key);
        return;
    }).on('error', function(unk, err) {
        alert(err); 
    });
})
;

$(document).on($.modal.CLOSE, function() {
    document.title = page_title;
});
