/*#########################################################################
# VINCE
#
# Copyright 2022 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for non-US
# Government use and distribution.
#
# Carnegie Mellon®, CERT® and CERT Coordination Center® are registered in the
# U.S. Patent and Trademark Office by Carnegie Mellon University.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM21-1126
########################################################################
*/

function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?                     
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

if (Dropzone) {
    Dropzone.autoDiscover = false;
}


$(document).ready(function() {

    var url = $("#replyform").attr("action");


    var simplemde = new EasyMDE({element: $("#id_content")[0],
                                   renderingConfig: {
                                       singleLineBreaks: false,
                                   },
				 status: false,
				 autoDownloadFontAwesome: false,
                                  });

    function submitFormWithoutFiles() {
	$('#sendbutton').prop('disabled', true);
	$("#sendbutton").html("Sending");
	$.ajax({
            url: $("#replyform").attr("action"),
            type: "POST",
            data: $('#replyform').serialize(),
            success: function(data) {
		simplemde.value("");
		$("#msglist").html(data);
		$('#sendbutton').prop('disabled', false);
		$("#sendbutton").html("Send");
            }
	});
    }

    var modal = $("#error_modal");
    
    $("#dropzonepreview").dropzone ({
	url: url,
	parallelUploads: 5,
	uploadMultiple: true,
	dictDefaultMessage: "",
	paramName: 'attachment',
	addRemoveLinks: true,
	autoProcessQueue: false,
	init: function() {
	    var myDropZone = this;
	    document.getElementById('replyform').addEventListener("submit", function(e) {
		e.preventDefault();
		e.stopPropagation();
		if (myDropZone.getQueuedFiles().length > 0) {
		    myDropZone.processQueue();
		} else {
		    var content = simplemde.value();
		    if (content != "") {
			submitFormWithoutFiles();
		    } else {
			modal.foundation('open');
		    }
		}
	    });
	    this.on("sendingmultiple", function(data, xhr, formData) {
		var form = document.getElementById('replyform');
		for(var i=0; i < form.elements.length; i++){
		    var e = form.elements[i];
		    console.log(e.name+"="+e.value);
		    formData.append(e.name, e.value);
		}
	    });
	    this.on("successmultiple", function(files, response) {
                simplemde.value("");
		myDropZone.removeAllFiles();
                $("#msglist").html(response);
            });

	}	
    });
    

    $("#id_to_user").change(function() {
	var input =  $(this).val();
	if (input != 0) {
	    $("#id_to_group").val(0);
	}
    });

    $("#id_to_group").change(function() {
        var input =  $(this).val();
        if (input != 0) {
            $("#id_to_user").val(0);
        }
    });


     var filter_msg = document.getElementById("filter_threads");
    if (filter_msg) {
	filter_msg.addEventListener("keyup", function(event) {
            searchThreads(event);
	});
    }
    
    $(document).on("change", '#id_subject', function(event) {
	var queue = $("#id_subject option:selected").val();
	if (queue == 2) {
	    $("#case_selection").removeClass("collapse");
	    $("#ga_selection").addClass("collapse");
	} else if (queue == 4) {
	    $("#ga_selection").removeClass("collapse");
	    $("#case_selection").addClass("collapse");
	    $("#id_case").val("");
	} else {
	    $("#case_selection").addClass("collapse");
	    $("#ga_selection").addClass("collapse");
	    $("#id_case").val("");
	}
    });


});
