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
	let content = $('#id_content').val();
	if($('#psirt_url').val()) {
	    content = content + "\n\nFollowing PSIRT Information " +
		"can be used to validate the Organization identity:\n\n" +
		"PSIRT URL   : " + $('#psirt_url').val() + "\n\n";
	} else if($('#group_admin_inactive').is(':checked')) {
	    content = content + "\n\n***Note*** Current Group Administrator " +
		"for this organization is no longer active! ";
	    $('#vendor_euid').val('');
	}
	$('#id_content').val(content);
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
    function get_cases() {
	var selected_case = $("#id_case option:selected").val();
	if(selected_case)
            $.ajax({
                url: '/vince/comm/auto/api/coord/'+selected_case,
                type: "GET",
                success: function(data) {
                    $("#coords_list").html(data);
                }
            });
    }
    $(document).on("change", '#id_case', get_cases);
    function old_vendor_info() {
	$('.new-vendor').remove();
	if($('.old-vendor').length)
	    return;
	let info = $("<div>");
	info.append($("<div>").addClass("new-vendor"));
	/*
	  {name: "psirt_email",
		       label: "Vendor PSIRT/Security Contact Email",
		       type: "text", example: "psirt@example.com"},
	*/
	let fields = [{name: "group_admin_inactive",
		       label: "Current Group Admin is no longer active",
		       placeholder: "Current Group Admin is no longer active",
		       type: "checkbox"}];
	fields.forEach(function(d) {
	    info.append($('<div>').addClass("form-group old-vendor")
			.append($("<input>").attr({id: d.name,
						   type:d.type,
						   name:d.name,
						   placeholder:d.example,
						   autocomplete:"off",
						   maxlength:"255"}))
			.append($("<label>").attr("for",d.name)
				.html(d.label)));
	});
	$('#id_vendor').parent().after(info.html());
    }
    function new_vendor_info() {
	$('#vendor_euid').val('');
	$('.old-vendor').remove();
	if($('.new-vendor').length)
	    return;
	let info = $("<div>");
	info.append($("<div>").addClass("new-vendor"));
	/*
	  {name: "psirt_email",
		       label: "Vendor PSIRT/Security Contact Email",
		       type: "text", example: "psirt@example.com"},
	*/
	let fields = [{name: "psirt_url",
		       label: "Vendor PSIRT/Security Public URL",
		       type: "text", example: "https://example.com/psirt"}]
	fields.forEach(function(d) {
	    info.append($('<div>').addClass("form-group new-vendor")
			.append($("<label>").attr("for",d.name)
				.html(d.label))
			.append($("<input>").attr({id: d.name,
						   type:d.type,
						   name:d.name,
						   placeholder:d.example,
						   autocomplete:"off",
						   maxlength:"255"})));
	});
	$('#id_vendor').parent().after(info.html());
    }
    function vend_auto() {
	if($('#vendor_euid').length < 1) {
	    $('#sendmsgform')
		.append($("<input>")
			.attr({type: "hidden",
			       name: "vendor_euid",
			       id: "vendor_euid"}))
	} else {
	    console.log("Already populated the vendor_auto fields");
	    return;
	}
	$.getJSON("/vince/comm/auto/api/allvendors").done(
	    function(data) {
		data.vendors.forEach(function(x) {
		    x.value = x.vendor_name;
		});
		/* Set difference on a object array */
		let tdata = data.vendors.filter(function(x) {
		    if(data.my_vendors.find(function(y) {
			return y.vendor_name == x.vendor_name
		    }))
			return false;
		    else
			return true
		});
		$("#id_vendor").addClass("ui-autocomplete-input")
		    .autocomplete({
			/* all vendors exept my own vendor group*/
			source: tdata,
			select: function (_, ui) {
			    $('#id_vendor').val(ui.item.vendor_name);
			    $('#vendor_euid').val(ui.item.euid);
			    return false;
			},
			change: function (_, ui) {
			    if(ui.item) {
				old_vendor_info();
			    } else {
				new_vendor_info();
			    }}});
	    });
    }
    if(!$('#vendor_selection').hasClass('collapse')) {
	$('label[for="id_content"]').html("Justification for access");	
	vend_auto();
    } else {
	$('label[for="id_content"]').html("Content");	
    }
    $(document).on("change", '#id_subject', function(event) {
	var t = $(this).attr("type");
	if (t == "text"){
	    /* if the field is a text field, don't change other fields */
	    return;
	}
	var queue = $("#id_subject option:selected").val();
	if (queue == 2) {
	    $("#case_selection").removeClass("collapse");
	    get_cases();
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
	    /* Auto populate vendor */
	    vend_auto();
	} else {
	    $("#case_selection").addClass("collapse");
	    $("#ga_selection").addClass("collapse");
	    $("#report_selection").addClass("collapse");
	    $("#vendor_selection").addClass("collapse");
	    $("#id_case").val("");
	}
    });
    
});
