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

function re_init_tooltips() {
    $('span[title]').qtip({
        style: {classes: 'qtip-youtube'}
    });
    $('i[title]').qtip({
        style: {classes: 'qtip-youtube'}
    });	
}


$(document).ready(function() {

    var modal = $("#rmusermodal");
    
    $("#adduserform").submit(function(event) {
        event.preventDefault();
        var url = $(this).attr("action");

	$.ajax({
            url: url,
            type: "POST",
            data: $('#adduserform').serialize(),
	    success: function(data) {
		if (data['response'] != "success"){
		    $("#addusermodal").foundation('close');
		    $("#errormsg").html(data['response']);
		    $("#adduser").val("");
		    $("#username").val("");
		    $("#errormodal").foundation('open');
		} else {
		    location.reload();
		}
	    }
        });
	$("#addusermodal").foundation('close');
    });

    
    $(document).on("click", '.rmuser', function(event) {
	event.preventDefault();
	var url = $(this).attr("href");
	$.ajax({
            url: url,
            success: function(data) {
		modal.html(data).foundation('open');
	    },
	});
    });

    $(document).on("click", '.caseaccess', function(event) {
	event.preventDefault();
	var url = $(this).attr("href");
	$.ajax({
            url: url,
            success: function(data) {
                modal.html(data).foundation('open');
            },
        });
    });

    $(document).on("click", '.adminuser', function(event) {
        event.preventDefault();
        var url = $(this).attr("href");
        $.ajax({
            url: url,
            success: function(data) {
                modal.html(data).foundation('open');
            },
        });
    });

    $(document).on("submit", '#confirmform', function(event) {
	event.preventDefault();
	 $.post($(this).attr("action"), $(this).serializeArray(),
		function(data) {
		    $.ajax({
			url: $("#user_table").attr("href"),
			success: function(data) {
                            $("#user_table").html(data);
			    re_init_tooltips();
			}
                    });
		});

	modal.foundation('close');
    });


    $(document).on("submit", '#accessform', function(event) {
        event.preventDefault();
         $.post($(this).attr("action"), $(this).serializeArray(),
                function(data) {
                    $.ajax({
                        url: $("#user_table").attr("href"),
                        success: function(data) {
                            $("#user_table").html(data);
			    re_init_tooltips();
                        }
                    });
                });

        modal.foundation('close');
    });
    
    $(document).on("click", "#select_all", function(event) {
        var status = $(this).is(':checked');
        $(':checkbox[name=access]').prop("checked", status);
    });

    $(document).on("change", "#accessSwitch", function(event) {
	var url = $(this).attr("href");
	$.ajax({
	    url: url,
	    type: "POST",
	    data: $('#accessForm').serialize(),
	    success: function(data) {
		$.ajax({
		    url: $("#user_table").attr("href"),
		    success: function(data) {
			$("#user_table").html(data);
			re_init_tooltips();
		    }
		});
	    }
	});
    });

    $(document).on("click", "#createservice", function(event) {
	var url = $(this).attr("href");
	event.preventDefault();
	$.ajax({
            url: url,
            success: function(data) {
                modal.html(data).foundation('open');
            },
        });
    });


    $(document).on("click", ".modemail", function(event) {
        var url = $(this).attr("href");
        event.preventDefault();
        $.ajax({
            url: url,
            success: function(data) {
                modal.html(data).foundation('open');
            },
        });
    });
    

    $(document).on("submit", "#genservice", function(event) {
	event.preventDefault();
	var url = $(this).attr("action");

        $.ajax({
            url: url,
            type: "POST",
            data: $('#genservice').serialize(),
            success: function(data) {
                if (data['response'] != "success"){
                    modal.foundation('close');
                    $("#errormsg").html(data['response']);
                    $("#errormodal").foundation('open');
                } else {
		    modal.foundation("close");
		    $.ajax({
			url: data["action"],
			success: function(data) {
			    modal.html(data).foundation('open');
			},
		    });
                }
            }
        });
        modal.foundation('close');
    });

    $(document).on("click", "#gentoken", function(event) {
        event.preventDefault();
        var url = $(this).attr("action");

        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
            }
        });

    });
    function callout(msg,level,autofade) {
	let close = $('<button>').addClass("close-button callout-close")
	    .append($('<span>').html('x'));
	$('.novosti')
	    .append($('<div>')
		    .addClass("callout warning tempr")
		    .text(msg)
		    .append(close));
	$('.tempr').on('click', function() {
	    $(this).remove();
	});
	if(autofade) 
	    setTimeout(function() {
		$('.tempr').fadeOut('slow',function() {
		    $(this).remove();
		});
	    },5000);
    }
    function review_uar(e) {
	let tr = $(e.target).closest('tr');
	let result = tr.data('userinfo');
	let modal = $('#addusermodal');
	let original = modal.html();
	modal.find(".close-button").on('click', function(event) {
	    modal.html(original);
	    modal.foundation('close');
	});
	if(!result)
	    return false;
	if(!('username' in result))
	    return false;
	let icss = {"border": "0px none","pointer-events": "none",
		    "font-weight": "bold","box-shadow": "none"};
	modal.find(".modal-body > p.lead").remove();
	let content = modal.find(".modal-body > p").html()
	    .replace("inviting","approving");
	modal.find(".modal-body > p").html(content);
	modal.find(".modal-title").html("Approve User to join " +
					"VINCE Group");
	modal.find("input#adduser").val(result.username).css(icss);
	modal.find("input#username").val(result.full_name).css(icss);
	modal.find("label").css({'padding-top': '6px'});
	modal.find(".required").remove();
	if(result.thread_url)
	    modal.find(".modal-body")
	    .append($('<div>').addClass("row").css("text-align","right")
		    .append($("<a>").attr({href:result.thread_url})
			    .html("View Full Message")));
	if(result.justification)
	    modal.find(".modal-body")
	    .append($('<div>').addClass('row')
		    .append($('<div>').addClass("large-2 columns text-right")
			    .html("Notes:"))
		    .append($('<div>').addClass("large-10 columns")
			    .css("max-height","40px")
			    .text(result.justification)));
	modal.foundation('open');
	let reject = $('<button>').addClass("button cmu")
	    .attr("id","reject").html("Reject").append(" ");
	let fbutton = modal.find('.modal-footer').find('.primary');
	fbutton.val('Approve').before(reject).before("&nbsp;&nbsp;");
	function reject_user(e) {
	    if(confirm("Are you sure?\n You want to reject this " +
		       "request and report this user to VINCE  "+
		       "Administrators")) {
		modal.foundation('close');
		tr.remove();
		let complaint = {csrfmiddlewaretoken: getCookie('csrftoken'),
				 subject: 1};
		complaint.content = $('.complaint').html();
		complaint.content = complaint.content
		    .replace(/\$([A-Za-z0-9_]+)/gi,
			     function(_,x) {
				 return result[x] || "";
			     });
		$.post($('#uartable').data('sendmsg'),complaint)
		    .done(function(d) {
			console.log(d);
			let msg = "The user has been reported to " +
			    "System Administrators of abuse!";
			callout(msg,"warning",true)
		    });
		complete_request(0,tr,result);
		return false;
	    }
	    return false;
	}
	$('#reject').on('click', function() { reject_user(); return false; });
	fbutton.on('click',function() {
	    complete_request(1,tr,result)
	});
	return false;
    }
    function complete_request(status,tr,result) {
	tr.remove();
	$.post($('#uartable').data('href'),
	       {csrfmiddlewaretoken: getCookie('csrftoken'),
		status: status,
		pk:result.pk,
		username:result.username});
	if($('.uar-dynamic').length < 1)
	    $('.uar').addClass("hide");
	    
    }
	
    $.getJSON($('#uartable').data('href'))
	.done(function(rdata) {
	    if("uar" in rdata)
		data = rdata.uar;
	    else
		return console.log("Failed to data payload " +
				   JSON.stringify(data));
	    let url_parts = location.href.split(/\/+/);
	    if(url_parts[url_parts.length - 2].match(/^\d+$/)) {
		let pk = parseInt(url_parts[url_parts.length - 2]);
		data = data.filter(function(x) {
		    return parseInt(x.pk) == pk;
		});
	    }
	    if(data.length &&
	       data.findIndex(function(d) { return 'pk' in d; }) > -1) {
		$('.uar').removeClass("hide");
		for(let i = 0; i < data.length; i++) {
		    let request_time = data[i].created_at;
		    let buttons = $('<span>')
			.append($("<button>").addClass("primary button")
				.html("Review"));
		    let tr = $('<tr>').append($('<td>').html(data[i].username))
			.append($('<td>').text(data[i].full_name))
			.append($('<td>').text(request_time)
				.addClass('datetimefield'))
			.append($('<td>').html(buttons))
			.addClass('uar-dynamic')
			.attr("data-userinfo",JSON.stringify(data[i]));
		    $('#uartable').append(tr);		    
		}
		$('#uartable button.primary').on('click', review_uar);
	    }
	    if(typeof(update_locales) == 'function')
		update_locales();
        })
	.fail(function() {
	    console.log(arguments);
	});
});
