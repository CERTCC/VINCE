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


function permissionDenied(modal) {

    modal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: You are not permitted to perform this action</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');

}


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

function Removefile(event) {
    event.preventDefault();
    var input = $("#file-title-wrap");
    input.replaceWith(input.val('').clone(true));
    $("#file-title-wrap").hide();

}

function add_tag(ticketcc_taggle, tag, modal){
    var csrftoken = getCookie('csrftoken');
    var url = $("#ticketcc_taggle").attr("action");
    $.post(url,
           {'csrfmiddlewaretoken': csrftoken, 'tag': tag, 'add_tag': true}, function(data) {
	       console.log("success adding");
           })
        .fail(function (data) {
	    console.log(data);
	    if (data['responseJSON']['error']) {
		modal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+data['responseJSON']['error']+"</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\"> Ok</a></div></div></div>").foundation('open');
		ticketcc_taggle.remove(tag);
	    } else {
		permissionDenied(modal);
		ticketcc_taggle.remove(tag);
	    }
        });
}

function del_tag(ticketcc_taggle, tag, modal){
    var csrftoken = getCookie('csrftoken');
    var url = $("#ticketcc_taggle").attr("action");
    $.post(url,
           {'state': 0, 'csrfmiddlewaretoken': csrftoken, 'tag': tag, 'del_tag':true}, function (data) {
	       console.log("success removing");
           })
        .fail(function (data) {
	    if (data['error']) {
		alert("An error occurred while trying to delete this tag: " + data['error']);
		ticketcc_taggle.add(tag);
	    } else {
		permissionDenied(modal);
		ticketcc_taggle.add(tag);
	    }
        });
    
}


function auto(data, taggle, modal) {
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
                add_tag(taggle, data.item.label, modal)
            }
        }
    });
}

$(document).ready(function() {

    if (document.getElementById('ticketcc_taggle') && document.getElementById('old_tags')) {
        var csrftoken = getCookie('csrftoken');
	var old_tags = JSON.parse(document.getElementById('old_tags').textContent);
	var other_tags = JSON.parse(document.getElementById('other_tags').textContent);
        /*var subscribed_users = JSON.parse(document.getElementById('subscribed_users').textContent);
	  var assignable = JSON.parse(document.getElementById('assignable').textContent);*/
        var ticketcc_taggle = new Taggle('ticketcc_taggle', {
            tags: old_tags,
	    tagFormatter: function(li) {
		var node = li.querySelector('.taggle_text');
		var text = node.textContent;
		var link = '<a href="/vince/search/?q='+text+'&facet=Tickets"/>';
		$(node).wrapInner(link);
		return li;
	    },
	    duplicateTagClass: 'bounce',
	    allowedTags:other_tags,
            /*placeholder: ["Add a tag..."],*/
            onTagAdd: function (event, tag) {
                if (event) {
                    add_tag(ticketcc_taggle, tag, adddepmodal)
                }
            },
            onBeforeTagRemove: function (event, tag) {
		if (event) {
                    del_tag(ticketcc_taggle, tag, adddepmodal)
		}
                return true;
            },
        });
	auto(other_tags, ticketcc_taggle, adddepmodal);
	/*$.getJSON(window.href, {
          'subscribed_users': true,
          'csrfmiddlewaretoken': csrftoken
	  }, function (data) {
          subscribed_users = data['subscribed_users'];
          for (i=0; i < subscribed_users.length; i++) {
	  console.log(subscribed_users[i]);
          ticketcc_taggle.add(subscribed_users[i]);
          }
          auto(data['assignable_users'], ticketcc_taggle);
          });*/
    }
    
    
    $(document).on("click", '#reassign', function(event) {
		$("#assign_block").show();
		$(".assigned_to").hide();
    });

    $(document).on("click", '#editres', function(event) {
	event.preventDefault();
	var url = $(this).attr("href");
        $.ajax({
            url: url,
	    type: "GET",
            success: function(data) {
		adddepmodal.html(data).foundation('open');
            },
            error: function(xhr, status) {
                permissionDenied(adddepmodal);
            }
	});	
    });

    $("#filter_by_dropdown_select_all_0").click(function(){
        $("#id_vendor input[type=checkbox]").prop('checked', $(this).prop('checked'));

    });

    $( "#id_due_date" ).datepicker({dateFormat: 'yy-mm-dd'});
    
    $("#filter_by_dropdown_select_all_1").click(function(){
        $("#id_participants input[type=checkbox]").prop('checked', $(this).prop('checked'));
    });

    $("#filter_by_dropdown_select_all_2").click(function(){
	$("#id_communication_type input[type=checkbox]").prop('checked', $(this).prop('checked'));
    });

    $(document).on("change", "#id_attachment", function(event) {
        var input = $(this).val();
        var filename = input.replace(/^.*[\\\/]/, '');
        $("#file-title-wrap").html('<p>' + filename +'&nbsp&nbsp<a href="#" class="removefile"><i class="fas fa-times-circle"></i></a></p>');
        $("#file-title-wrap").show();
        if ($("#id_title")) {
            $("#id_title").val(filename);
            $("#id_value").val(filename);
        }
    });

    var status_change = false;
    $(document).on("change", 'input[type=radio][name=new_status]', function(event) {
	status_change = true;
    });
    
    $(document).on("click", ".removefile", function(event) {
        Removefile(event);
    });
    

    $(document).on("change", '#id_queue', function(event) {
	var queue = $("#id_queue option:selected").text();
	if (queue == "Case") {
	    $("#casefield").show();
	} else {
	    $("#casefield").hide();
	}
    });
    
    $(document).on("click", "#assign_submit", function(event) {
		var val = $("#uassign option:selected").val();
		var name = $("#uassign option:selected").html();
		var url = window.location.href.split('#')[0] + "?assign="+val;

		if (val == "-2") {
			var url = window.location.href.split('#')[0] + "?autoassign=1";
			
			$.ajax({
				url: url,
				type: "GET",
				success: function(data) {
					adddepmodal.html(data).foundation('open');
				},
				error: function(xhr, status) {
					permissionDenied(adddepmodal);
				}
			});

		} else {
			$.ajax({
			url: url,
			type: "GET",
			success: function(data) {
				if (val == 0) {
				$(".assigned_to_name").html("Unassigned");
				$(".assigned_to").html($("#reassignblock").html());
				} else {
				$(".assigned_to_name").html(name);
				}
			},
			error: function(xhr, status) {
				permissionDenied(adddepmodal);
			}
			});

			$("#assign_block").hide();
			$(".assigned_to").show();
		}
    });

    var role = document.getElementById('assignrole');
    if (role) {

	var val = $("#id_assigned_to option:selected").val();

	if (val == "-2") {
	    $("#assignrole").show();
	}
	
	$(document).on("change", "#id_assigned_to", function(event) {
	    var val = $("#id_assigned_to option:selected").val();
	    if (val == "-2") {
		$("#assignrole").show();
	    } else {
		$("#assignrole").hide();
	    }
	    
	});
    }

    $(document).on("submit", "#assignform", function(event) {
	event.preventDefault();
	var csrftoken = getCookie('csrftoken');
	var val = $('input[name="role"]:checked').val();
	var url = $(this).attr("action");
	var pdata = {'role': val, 'csrfmiddlewaretoken': csrftoken};
        $.ajax({
	    url:url,
	    type: "POST",
	    data: pdata,
	    success:function(data) {
		adddepmodal.foundation('close');
		$(".assigned_to_name").html(data['assignment']);

            },
	    error: function(xhr, status) {
		var data = JSON.parse(xhr.responseText);
		adddepmodal.foundation('close');
		if (data['error']) {
		    adddepmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+data['error']+"</p> <div class=\"modal-footer text-right\"><ahref=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
		} else {
                    permissionDenied(adddepmodal);
		}
	    }
	});
	$("#assign_block").hide();
	$(".assigned_to").show();
    });

    $(document).on("click", ".assigntome", function(event) {
	event.preventDefault();
	var url = $(this).attr("href");
	var name = $(this).attr("val");
	$.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		$(".assigned_to").html($("#reassignblock").html());
	    },
	    error: function(xhr, status) {
                permissionDenied(adddepmodal);
	    }
	});
        $(".assigned_to").show();
    });
    
    $(document).on("click", "#assign_cancel", function(event) {
        $("#assign_block").hide();
        $(".assigned_to").show();
    });

    var adddepmodal = $("#adddependency");
    
    $(document).on("click", ".followup-edit", function(event) {
	var url = $(this).attr("href");
	event.preventDefault();
	$.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                adddepmodal.html(data).foundation('open');
            },
	    error: function(xhr, status) {
                permissionDenied(adddepmodal);
	    }
        });

    });
    
    $(document).on("submit", "#followup-edit-form", function(event) {
        event.preventDefault();
        $.post($(this).attr("action"), $(this).serializeArray(),
               function(data) {
		   adddepmodal.foundation('close');
		   $.ajax({
		       url: $("#ticket_activity").attr("href"),
		       type: "GET",
		       success: function(tktdata) {
			   $("#ticket_activity").html(tktdata);
		       }
		   });   
               })
	    .fail(function(d) {
		permissionDenied(adddepmodal);
	    });

    });

    $(document).on("click", ".followup-submit", function(event) {
	event.preventDefault();
	var comment = $(this).closest('div').prev().prev().prev('textarea').val();
	var followup = $(this).attr("followup");
	var ticket = $(this).attr("ticket");
	var url = '/vince/followup_edit/'+ticket+'/'+followup+'/';
	var csrftoken = getCookie('csrftoken');
	var data = {'comment': comment, 'csrfmiddlewaretoken': csrftoken};
	$.post(url, data, function(data) {
	})
	    .fail(function(d) {
		permissionDenied(adddepmodal);
	    });
	var p = "<p>"+comment+"</p>";
	$(this).closest('div').prev().prev().prev('textarea').replaceWith(p);
	$(this).closest('div').hide();
	$(this).closest('div').prev().show();
	
    });

    $(document).on("click", ".followup-cancel", function(event) {
	event.preventDefault();
        var comment = $(this).closest('div').prev().prev().prev('textarea').val();
	var p = "<p>"+comment+"</p>";
        $(this).closest('div').prev().prev().prev('textarea').replaceWith(p);
        $(this).closest('div').hide();
        $(this).closest('div').prev().show();
    });


    $(document).on("click", ".adddependency", function(event) {
	event.preventDefault();
	var url = $(this).attr("action");
	$.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		adddepmodal.html(data).foundation('open');
	    },
	    error: function(xhr, status) {
                permissionDenied(adddepmodal);
	    }
	});
    });


    $(document).on("click", "#assignteam", function(event) {
        event.preventDefault();
	var url = $(this).attr("href");
        $.ajax({
            url: url,
	    type: "GET",
            success: function(data) {
		adddepmodal.html(data).foundation('open');
            },
	    error: function(xhr, status) {
                permissionDenied(adddepmodal);
	    }
        });
    });
    
    $(document).on("submit", "#commentform", function(event) {
		var new_status = $("input[name='new_status']:checked").val();
		if (new_status != 4) {
			return;
		}
		if (status_change==false) {
			return;
		}
		var url = $(this).attr("confirm");
		console.log('url is ' + url )
		if (url) {
			event.preventDefault();
			$.ajax({
				url: url,
				type: "GET",
				success: function(data) {
					adddepmodal.html(data).foundation('open');
					$("#id_new_status").val(new_status);
					$("#id_comment").val($("#commentBox").val());
				},
				error: function(xhr, status) {
					permissionDenied(adddepmodal);
				}
			});
		} else { 
			return; 
		}
	
    });

    $(document).on("click", "#quickclose", function(event) {
	event.preventDefault();
	var url = $("#commentform").attr("action");
	$.post(url,
               {'csrfmiddlewaretoken': csrftoken, 'new_status':4},
               function(data) {})
	    .done(function() {
		/* redirect to referer */
		if (document.referrer) {
		    window.location.href = document.referrer;
		} else {
		    window.location.reload(true);
		}
	    })
	    .fail(function() {
		permissionDenied(adddepmodal);
	    });
    });


    $(document).on("click", "#encrypttkt", function(event) {
	event.preventDefault();
        var url = $(this).attr("href");
        if (url) {
            $.ajax({
                url: url,
                type: "GET",
                success: function(data) {
                    adddepmodal.html(data).foundation('open');
		},
		error: function(xhr, status) {
                    permissionDenied(adddepmodal);
		}
            });
	}
    });

    $('.scrollnext').click(function () {
	var scrollnext = $(this).parent().parent().parent().next().offset();
	if (scrollnext) {
	    $("html, body").animate({
		scrollTop: $(this).parent().parent().parent().next().offset().top
	    }, 600);
	} else {
	    $("html, body").animate({
		scrollTop: $(this).parent().offset().top
	    }, 600);
	}
        return false;
    });
    
    $('.edit-btn').qtip({
	content: 'Reply to Email',
        style: {classes: 'qtip-youtube'},
	position: {
	    corner: {
		target:'bottomLeft',
		tooltip: 'bottomLeft'
	    },
	    adjust: {
		x:-60,
		y:5
	    }
	}
    });
    
    
    $('.email-detail').each(function () {
        $(this).qtip({
	    content: $(this).attr("title"),
	    style: {classes: 'qtip-youtube'},
	    position: {
		corner: {
		    target:'bottomLeft',
		    tooltip: 'bottomLeft'
		},
		adjust: {
		    x:-60,
		    y:5
		}
	    }
	});
    });
    $(document).keypress(function(event) {
	var keycode = (event.keyCode ? event.keyCode : event.which);
	if(keycode == '13'){
	    if (document.getElementById('why_close_form')) {
		var send_email = $('input[name="send_email"]:checked').val();
		if (send_email == '1') {
		    $("#why_close_form").submit();
		    return false;
		}
	    } else if (document.getElementById('assignteamform')) {
		/* ideally there would be a check to see if the reveal was actually open */
		$("#assignteamform").submit();
		return false;
	    }
	}
    });

    function searchVendors(vendor) {
	var url = $("#msgadmin").attr("href");
	var csrftoken = getCookie('csrftoken');
	
	$.ajax({
            url: url,
            type: "POST",
            data: {'csrfmiddlewaretoken':csrftoken, 'vendor': vendor, 'email':$("#msgadmin").attr("email")},
            success: function(data) {
		$("#vendor-results").html("<p>" + data['text'] + "</p><p><a href=\""+ data['contact_link']+"\">View Contact</a> <b>OR</b> <a href=\""+data['email_link']+"\">Request Authorization via Email</a></p>")
		if (data['msg_link']) {
		    $("#msgadminform").attr("action", data['msg_link']);
		    $("#msgabutton").prop("disabled", false);
		    $("#id_msg").val(data['msg_body']);
		    $("#msgvendor").removeClass("hidden");
		} else if (data['action_link']) {
		    $("#msgvendor").addClass("hidden");
		    let send_email = $("<div>")
			.append($("<a>").addClass("button primary")
				.prop("href",data.action_link)
				.html("Send Email")).html()
		    $("#msgabutton").replaceWith(send_email);
		} else {
		    $("#msgvendor").addClass("hidden");
		    $("#msgabutton").prop("disabled", true);
		}
            }
	});
    }
    
    function vend_auto(data) {
	var vendor_input = $('input[id="vendor"]');
	vendor_input.autocomplete({
	    source: data,
	    minlength: 2,
            select: function(event, data) {
		console.log(data.item.value);
		if (data.item.value) {
		    searchVendors(data.item.value);
		} else {
		    $("#msgvendor").addClass("hidden");
		    $("#msgabutton").prop("disabled", true);
		    $("#vendor-results").html("<p>No contact found. <a href=\"/vince/create/contact/\">Create a new contact.</a></p>" );
		}
            },
	    response: function(event, ui) {
		if (!ui.content.length) {
		    var noResult = { value:"",label:"No results found" };
		    ui.content.push(noResult);
		}
	    }
	});
    }
    function msgadminform_async() {
        $('#msgadminform').on('submit',function(e) {
        e.preventDefault();
        $('body').css({opacity: 0.5});
        $.post(this.action,$(this).serialize(),function(d) {
            console.log(d);
            $('#msgadminform .modal-body').html('<h2>Submit completed</h2>')
                .append(JSON.stringify(d,null,'\t'));
        }).fail(function() {
	    $('#msgadminform .modal-body').html('<h2>Submission Failed!<h2>')
		.append("See console log for details");
	    console.log(arguments);
	}).done(function() {
            $('#msgadminform .modal-footer').html('');
            setTimeout(function() {
                $("#adddependency").foundation('close');
                location.reload();
            }, 900);
        });
        return false;
	});
    }
    $(document).on("click", "#msgadmin", function(event) {
        event.preventDefault();
        var url = $(this).attr("href");
        if (url) {
            $.ajax({
                url: url,
                type: "GET",
                success: function(data) {
                    adddepmodal.html(data).foundation('open');
		    $.getJSON("/vince/api/vendors/", function(data) {
			vend_auto(data);
			msgadminform_async();
		    });
                },
                error: function(xhr, status) {
                    permissionDenied(adddepmodal);
                }
            });
        }
    });
});

