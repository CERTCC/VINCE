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

function deleteRow(btn) {
    var row = btn.parent().parent();
    row.remove();
}


function reloadActivity() {
    $.ajax({
	url: $("#activitypanel").attr("action"),
	success: function(data) {
            $("#activitypanel").html(data);
	}
    });
}

function add_group(taggle, group) {
    var csrftoken = getCookie('csrftoken');
    var url = $("#group_taggle").attr("action");
    $.post(url,
           {'csrfmiddlewaretoken': csrftoken, 'group': group},
	   function(data) {
               console.log("success adding");
               reloadActivity();
           })
        .fail(function (data) {
            alert("An error occurred while trying to add this group: " + data['responseJSON']['error']);
            taggle.remove(group);
        });
}

function del_group(taggle, group) {
    var csrftoken = getCookie('csrftoken');
    var url = $("#group_taggle").attr("action");
    $.post(url,
           {'rm': 1, 'csrfmiddlewaretoken': csrftoken,
            'group': group}, function (data) {
                console.log("success removing");
                reloadActivity();

            })
        .fail(function (data) {
            alert("An error occurred while trying to delete this tag: " + data['responseJSON']['error']);
            taggle.add(group);
        });
}


function add_admin(user, url){
    var csrftoken = getCookie('csrftoken');
    $.post(url,
           {'csrfmiddlewaretoken': csrftoken, 'user': user, 'add_admin': true}, function(data) {
               console.log("success adding");
	       window.location.reload(true);
           })
        .fail(function (data) {
            alert("An error occurred while trying to add admin: " + data['responseJSON']['error']);
        });
}

function del_admin(user, url){
    var csrftoken = getCookie('csrftoken');
    $.post(url,
           {'state': 0, 'csrfmiddlewaretoken': csrftoken,
	    'user': user, 'del_admin':true}, function (data) {
		console.log("success removing");
		window.location.reload(true);
		
            })
        .fail(function (data) {
            alert("An error occurred while trying to remove admin permissions: " + data['responseJSON']['error']);
        });
}

function add_tag(taggle, tag){
    var csrftoken = getCookie('csrftoken');
    var url = $("#contact_taggle").attr("action");
    $.post(url,
           {'csrfmiddlewaretoken': csrftoken, 'tag': tag, 'add_tag': true}, function(data) {
               console.log("success adding");
               reloadActivity();
           })
        .fail(function (data) {
            alert("An error occurred while trying to add this tag: " + data['responseJSON']['error']);
            taggle.remove(tag);
        });
}


function del_tag(taggle, tag){
    var csrftoken = getCookie('csrftoken');
    var url = $("#contact_taggle").attr("action");
    $.post(url,
           {'del_tag': true, 'csrfmiddlewaretoken': csrftoken,
            'tag': tag}, function (data) {
                console.log("success removing");
                reloadActivity();

            })
        .fail(function (data) {
            alert("An error occurred while trying to delete this tag: " + data['responseJSON']['error']);
            taggle.add(tag);
        });
}


function auto(data, taggle) {
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
                add_group(taggle, data.item.label)
            }
        }
    });
}


function searchTasks(e) {
    var csrftoken = getCookie('csrftoken');

    if (e) {
        e.preventDefault();
    }

    var url = $("#filter_tasks").attr("href");
    var sort = $("#filterstatus option:selected").val();
    var name = $("#filter_tasks").attr("name");
    $.ajax({
        url : url,
        type: "POST",
        data: {"wordSearch": $("#filter_tasks").val(),
               "csrfmiddlewaretoken": csrftoken,
               "sort": sort,
	       "contact": name,
              },
        success: function(data) {
            $("#case_tasks").html(data);
        }
    });
}

$(document).ready(function() {


    var filter_task = document.getElementById("filter_tasks");
    if (filter_task) {
        filter_task.addEventListener("keyup", function(event) {
            searchTasks(event);
        });
    }

    $("#filterstatus").change(function(event) {
        searchTasks(event);
    });

    

    if (document.getElementById('group_taggle')) {
	var contact_groups = JSON.parse(document.getElementById('groups').textContent);
        var assignable = JSON.parse(document.getElementById('all_groups').textContent);
        var group_taggle = new Taggle('group_taggle', {
            tags: contact_groups,
            duplicateTagClass: 'bounce',
            allowedTags: assignable,
	    preserveCase: true,
            placeholder: ["Add a group..."],
            onTagAdd: function (event, tag) {
                if (event) {
                    add_group(group_taggle, tag)
                }
            },
            onBeforeTagRemove: function (event, tag) {
                del_group(group_taggle, tag)
                return true;
            },
        });
        auto(assignable, group_taggle);
    }

    if (document.getElementById('contact_taggle')) {
        var tags = JSON.parse(document.getElementById('contact_tags').textContent);
        var availtags = JSON.parse(document.getElementById('other_tags').textContent);
        var contact_taggle = new Taggle('contact_taggle', {
            tags: tags,
            duplicateTagClass: 'bounce',
            allowedTags: availtags,
            placeholder: ["Tag this Contact..."],
            tagFormatter: function(li) {
                var node = li.querySelector('.taggle_text');
		var text = node.textContent;
                var link = '<a href="/vince/contacts/search/?q='+text+'"/>';
                $(node).wrapInner(link);
                return li;
            },

            onTagAdd: function (event, tag) {
		if (event) {
                    add_tag(contact_taggle, tag)
                }
            },
            onBeforeTagRemove: function (event, tag) {
		if (event) {
                    del_tag(contact_taggle, tag)
		}
                return true;
            },
        });
	auto(availtags, contact_taggle);
    }

    $(document).on("input", "#id_msg", function(event) {
	$("#msgabutton").prop("disabled", false);
    });
    
    $(document).on("click", "#rejectchange", function(event) {
	event.preventDefault();
        var url = $(this).attr("action");
	$.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                $modal.html(data).foundation('open');
            }
        });
    });
    var $modal = $("#modal");
    $(document).on("click", "#previewchange", function(event) {
        event.preventDefault();
	var url = $(this).attr("action");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                $modal.html(data).foundation('open');
            }
        });
    });


    $(".assigned").on("click", "a", function(event) {
	event.preventDefault();
        var assign_block = $("#task_assign").html();
        $(this).parent().hide();
        $(this).parent().parent().append(assign_block);
    });

    $(".task_status").on("click", "a", function(event) {
        event.preventDefault();
        var href = $(this).parent().parent().attr("href");
        var csrftoken = getCookie('csrftoken');
        $.post(href,
            {'csrfmiddlewaretoken': csrftoken, 'new_status':$(this).attr("val")},
            function(data) {})
            .done(function(data, textStatus, jqXHR) {
                console.log("post succeeded (textStatus: " + textStatus + ")");
                window.location.reload(true);
            });
    });


    $('#showcharttip').qtip({
        content: $("#vendor_type_help"),
        style: {classes: 'qtip-youtube'}
    });

    $('#showtypehelp').qtip({
        content: $("#email_type_help"),
        style: {classes: 'qtip-youtube'}
    });

    $(document).on("click", ".adminuser", function(event) {
	event.preventDefault();
	add_admin($(this).attr("val"), $(this).attr("href"));
    });

    $(document).on("click", ".rmadminuser", function(event) {
	event.preventDefault();
	del_admin($(this).attr("val"), $(this).attr("href"));
    });

    $(document).on("click", ".task_assign_cancel", function(event) {
        $(this).parent().prev().show();
        $(this).parent().remove();

    });

    $(document).on("click", ".task_assign_submit", function(event) {
        /*var txt = $(this).prev();*/
        var val = $(".task_reassign:last").val();
        var href = $(this).parent().parent().parent().attr("href");
        var url = href + "?assign="+val;
        $.get(url, function(data) {})
	.done(function() {
            window.location.hash ='#tickets';
            window.location.reload(true);
        });
    });

    $(document).on("click", "#adduser", function(event) {
	event.preventDefault();
        var url = $(this).attr("href");
	$.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		$modal.html(data).foundation('open');
            }
        });
    });

    $(document).on("click", ".rmemail", function(event) {
	event.preventDefault();
	var url = $(this).attr("href");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		$modal.html(data).foundation('open');
            }
        });
    });
    
    $(document).on("click", "#addemail", function(event) {
	event.preventDefault();
	var url = $(this).attr("href");
	$.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		$modal.html(data).foundation('open');
            }
	});
    });

    $(document).on("submit", "#addemailform", function(event) {
	event.preventDefault();
	var url = $("#addemailform").attr("action");
	$.ajax({
            url: url,
            type: "POST",
	    data: $("#addemailform").serialize(),
            success: function(data) {
		console.log(data);
		if (data['ticket']) {
		    location.href = data['ticket'];
		}
		else if (data['refresh']) {
		    window.location.reload(true);
		} else if (data['msg_body']){
		    $("#vendor-results").html("<p><b>" + data['text'] + " Or <a href=\""+ data['email_link'] + "\">Request Authorization via Email</a></b></p>")
                    $("#id_msg").val(data['msg_body']);
                    $("#msgvendor").removeClass("hidden");
		} else {
		    $("#vendor-results").html("<p><b><span class=\"error\">" + data['text'] +"</span></b></p>");
		    if (data['bypass']) {
			$("#vendor-results").append("<p><a href=\"" + data['bypass'] + "\">Request Internal Validation for this Email</a></p>");
		    }
		}
            }
	});
    });

});
