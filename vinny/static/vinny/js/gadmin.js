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

    $(document).on("click", ".closemodal", function(event) {
	location.reload();
    });
    
});
