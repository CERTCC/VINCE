/*#########################################################################
# VINCE
#
# Copyright 2023 Carnegie Mellon University.
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

function autoTaggle(data, taggle) {
    var container = taggle.getContainer();
    var input = taggle.getInput();
    $(input).autocomplete({
        source: data,
        appendTo:container,
        position: { at: "left bottom", of: container },
        select: function(event, data) {
            event.preventDefault();
            if (event.which === 1) {
                taggle.add(data.item.value);
		if (container.id == "id_to_group") {
		    add_tag(taggle, data.item.label);
		}
            }
        }
    });
}

var emails = {};

function del_tag(taggle, tag){
    var csrftoken = getCookie('csrftoken');
    var url = $("#lookup_org").attr("action");
    var vcase = $("#lookup_org").attr("title");
    
    $.post(url,
           {'csrfmiddlewaretoken': csrftoken, 'tag': tag, 'case': vcase}, function (data) {
               $.each(data["emails"], function(i, val) {
		   if (emails[val]) {
		       emails[val] = emails[val] - 1;
		   }
	       });
	       $("#show_emails").html("Users: ");
	       $.each(emails, function(k, val) {
		   if (val) {
		       $("#show_emails").append("<span class=\"send_email\">"+k+"</span>");
		   }
	       });
	       
		   
            })
        .fail(function (data) {

        });

}

function add_tag(taggle, tag){
    var url = $("#lookup_org").attr("action");
    var csrftoken = getCookie('csrftoken');
    var vcase = $("#lookup_org").attr("title");
    $.post(url,
           {'csrfmiddlewaretoken': csrftoken, 'tag': tag, 'case':vcase}, function(data) {
	       var emails = data["emails"];
	       if (emails && emails.length) {
		   $("#show_emails").removeClass("hidden");
		   $.each(data["emails"], function(i, val) {
		   
		       if (!emails[val]) {
			   emails[val] = 1;
			   $("#show_emails").append("<span class=\"send_email\">"+val+"</span>");
		       } else {
			   emails[val] = emails[val] + 1;
		       }
		   });
	       } else {
		   $("#errormodal").html('<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: This organization does not have any valid VINCE users.</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>"').foundation('open');
		   taggle.remove(tag);
	       }
           })
        .fail(function (data) {
            alert("An error occurred while trying to add this tag: " + data['error']);
        });
}

$(document).ready(function() {

    var url = $("#sendmsgform").attr("action");


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
            url: $("#sendmsgform").attr("action"),
            type: "POST",
	    data: $('#sendmsgform').serialize(),
            success: function(data) {
		var url_mask = $("#sendmsgform").attr("success");
		if ("url" in data) {
		    window.location = data["url"];
		} else {
                    window.location = url_mask;		    
		}
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
	    document.getElementById('sendmsgform').addEventListener("submit", function(e) {
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
		var form = document.getElementById('sendmsgform');
		for(var i=0; i < form.elements.length; i++){
		    var e = form.elements[i];
		    console.log(e.name+"="+e.value);
		    formData.append(e.name, e.value);
		}
	    });
	    this.on("successmultiple", function(files, response) {
		var url_mask = $("#sendmsgform").attr("success");
		if ("url" in response) {
		    window.location = response["url"];
		} else {
		    window.location = url_mask;
		}
            });

	}	
    });
    
    if (document.getElementById("")) {
	var tag_url = $("#group_taggs").attr("href");
        var assigned_users = JSON.parse(document.getElementById('assigned_users').textContent);
        var assignable = JSON.parse(document.getElementById('assignable').textContent);
        console.log(assignable);
        var tags = [];
        var taggle2 =  new Taggle('group_taggs', {
            tags: assigned_users,
            duplicateTagClass: 'bounce',
            preserveCase: true,
            allowedTags: assignable,
            placeholder: ["Tag a vendor..."],
	});
    }


    if (document.getElementById("id_to_user")) {
	var tags = [];
	if (document.getElementById('user_tags')) {
	    var user_tags = JSON.parse(document.getElementById('user_tags').textContent);
	} else {
	    var user_tags = [];
	}
        var user_taggle = new Taggle('id_to_user', {
            tags: user_tags,
            duplicateTagClass: 'bounce',
            preserveCase: true,
            placeholder: ["Select user(s)..."],
        });

	autoTaggle($("#id_to_user").attr("href"), user_taggle);
    }

    if (document.getElementById("id_to_group")) {
        var tags = [];
	if (document.getElementById('group_tags')) {
	    var group_tags = JSON.parse(document.getElementById('group_tags').textContent);
	    var assignable = [];
	} else if (document.getElementById('assignable')) {
	    var group_tags = [];
	    var assignable = JSON.parse(document.getElementById('assignable').textContent);   
	} else {
	    var group_tags = [];
	    var assignable = [];
	}
	var group_taggle = new Taggle('id_to_group', {
	    tags: group_tags,
            duplicateTagClass: 'bounce',
	    hiddenInputName: ["taggles_group[]"],
            preserveCase: true,
            placeholder: ["Select vendor(s)..."],
	    onTagAdd: function (event, tag) {
                if (event) {
                    add_tag(group_taggle, tag)
                }
            },
	    onTagRemove: function(event, tag) {
		del_tag(group_taggle, tag);
	    },
	    
        });

	if (assignable) {
	    group_taggle.allowedTags = assignable;
	    autoTaggle(assignable, group_taggle);
	} else {
	    autoTaggle($("#id_to_group").attr("href"), group_taggle);
	}
    }
    
/*    $("#id_attachment").change(function() {
        var input = $(this).val();
	var filename = input.replace(/^.*[\\\/]/, '');
	$("#file-title-wrap").html('<p>' + filename +'&nbsp&nbsp<a href="#" onClick="Removefile(event);"><i class="fas fa-times-circle"></i></a></p>');
$("#file-title-wrap").show();
	if ($("#id_title")) {
	    $("#id_title").val(filename);
	    $("#id_value").val(filename);
	}
});*/

    /*
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
    */

    $(document).on("submit", "#replyform", function(event) {
        event.preventDefault();
	$.ajax({
            url: $("#replyform").attr("action"),
            type: "POST",
            data: $('#replyform').serialize(),
            success: function(data) {
		simplemde.value("");
		$("#msglist").html(data);
            }
	});
    });
    
    var filter_msg = document.getElementById("filter_threads");
    if (filter_msg) {
	filter_msg.addEventListener("keyup", function(event) {
            searchThreads(event);
	});
    }

    $(document).on("change", '#id_case', function(event) {
	var selected_case = $("#id_case option:selected").val();
        $.ajax({
                url: '/vince/comm/auto/api/coord/'+selected_case,
                type: "GET",
                success: function(data) {
                    $("#coords_list").html(data);
                }
            });
    });
    
    $(document).on("change", '#id_subject', function(event) {
	var t = $(this).attr("type");
	if (t == "text"){
	    /* if the field is a text field, don't change other fields */
	    return;
	}
	var queue = $("#id_subject option:selected").val();
	if (queue == 2) {
	    $("#case_selection").removeClass("collapse");
	    var selected_case = $("#id_case option:selected").val();
	    $.ajax({
		url: '/vince/comm/auto/api/coord/'+selected_case,
		type: "GET",
		success: function(data) {
		    $("#coords_list").html(data);
		}
	    });
	    $("#ga_selection").addClass("collapse");
	    $("#report_selection").addClass("collapse");
	    $("#vendor_selection").addClass("collapse");
	} else if (queue == 4) {
	    $("#ga_selection").removeClass("collapse");
	    $("#case_selection").addClass("collapse");
	    $("#report_selection").addClass("collapse");
	    $("#id_case").val("");
	    $("#vendor_selection").addClass("collapse");
	} else if (queue == 9) {
	    $("#case_selection").addClass("collapse");
            $("#ga_selection").addClass("collapse");
	    $("#report_selection").removeClass("collapse");
	    $("#vendor_selection").addClass("collapse");
	} else if (queue == 10) {
	    $("#vendor_selection").removeClass("collapse");
	    $("#ga_selection").addClass("collapse");
            $("#case_selection").addClass("collapse");
            $("#report_selection").addClass("collapse");
	} else {
	    $("#case_selection").addClass("collapse");
	    $("#ga_selection").addClass("collapse");
	    $("#report_selection").addClass("collapse");
	    $("#vendor_selection").addClass("collapse");
	    $("#id_case").val("");
	}
    });
    

});
