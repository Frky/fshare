Dropzone.autoDiscover = false;

var page_title = document.title;

var init_dropzone = function(dz) {
    var fDropzone = new Dropzone(dz);
    form = $(dz);

    fDropzone.options.uploadMultiple = true;
    fDropzone.options.parallelUploads = 50;
    fDropzone.options.maxFiles = 50;

    fDropzone.on('addedfile', function (file) {
        // error_displayed = false;
        // if (ref_file == null)
        //     ref_file = file;
        // if (ref_file != file)
        //     return;
        // nanobar.go(0);
        // $(filter).removeClass("hidden");
        // $(".text", filter).html("uploading file&nbsp;");
        // routine = setInterval(waiting_for_file, 1000);
    }).on('uploadprogress', function(file) {
        // if (ref_file != file)
        //  return;
        // nanobar.go(file.upload.progress);
        // document.title = "FShare - Uploading " + Math.round(file.upload.progress) + "%";
        /*
        if (file.upload.progress == 100) {
            $(".text", filter).html("ciphering file ... please wait&nbsp;");
            $.removeCookie("fileReady");
            clearInterval(routine);
            routine = setInterval(waiting_for_file, 1000);
        }
        */
    }).on('complete', function(file) {
        // ref_file = null;
        // $(filter).addClass("hidden");
        // clearInterval(routine);
        if (file.xhr == undefined)
            return;
        if (file.xhr.response == "ERROR") {
            if (!error_displayed) {
                alert("An error occurred (quota exceeded?)");
                error_displayed = true;
            }
            return;
        }
        // document.title = "FShare - Upload completed"
        // var href =  "https://" + document.domain + "/dl/" + file.xhr.response;
        // var key = $("input#id_key").val();
        // if (key == undefined || key == " ")
        //    key = "";
        // show_link(href, key);
        location.reload();
        return;
    }).on('error', function(unk, err) {
        alert(err); 
    });
    return;
}

$(document).ready(function () {

    $(".update-form").each(function() {
        init_dropzone(this);
    });
});


/*
    var nanobar;
    var options = {
        id : "upload-progression",
        bg: "#8D608C"
    }
    var nanobar =  new Nanobar( options );

    var ref_file = null;
    var err_displayed = false;

})
;

$(document).on($.modal.CLOSE, function() {
    document.title = page_title;
});
*/
