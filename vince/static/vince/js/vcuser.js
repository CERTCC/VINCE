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

function searchTasks(e) {
    var csrftoken = getCookie('csrftoken');

    if (e) {
        e.preventDefault();
    }

    var url = $("#filter_tasks").attr("href");
    var sort = $("#filterstatus option:selected").val();
    var name = $("#filter_tasks").attr("name");
    lockunlock(true,'div.vtmainbody,div.mainbody','#case_tasks');
    window.txhr = $.ajax({
        url : url,
        type: "POST",
        data: {"wordSearch": $("#filter_tasks").val(),
               "csrfmiddlewaretoken": csrftoken,
               "sort": sort,
               "submitted_by": name,
              },
        success: function(data) {
	    lockunlock(false,'div.vtmainbody,div.mainbody','#case_tasks');
            $("#case_tasks").html(data);
        },
	error: function() {
            lockunlock(false,'div.vtmainbody,div.mainbody','#case_tasks');
            console.log(arguments);
            alert("Search failed or canceled! See console log for details.");
        },
        complete: function() {
            /* Just safety net */
            lockunlock(false,'div.vtmainbody,div.mainbody','#case_tasks');
            window.txhr = null;
        }
    });
}

function nextThreads(page) {
    var url = $("#filterform").attr("action") + "?page="+page;
    $.ajax({
        url : url,
        type: "GET",
        success: function(data) {
            $("#threads").html(data);
        }
    });
}

$(document).ready(function() {
    var $modal = $('#modal'); 
    $(document).on("click", "#rmuser", function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr('href'),
            type: "GET",
            success: function(resp) {
                $modal.html(resp).foundation('open');
            }
        });

    });

    $(document).on("click", '.search_notes', function(event) {
        var page = $(this).attr('next');
	event.preventDefault();
        nextThreads(page);
    });

    $(document).on("click", "#resetusermfa", function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr('href'),
            type: "GET",
            success: function(resp) {
                $modal.html(resp).foundation('open');
            }
        });

    });

    $(document).on("click", "#initiatereset", function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr('href'),
            type: "GET",
            success: function(resp) {
                $modal.html(resp).foundation('open');
            }
        });

    });
    
    
    $(document).on("click", '.approve', function(event) {
        event.preventDefault();
        var csrftoken = getCookie('csrftoken');
        var url = $(this).attr("href");

        $.post(url, {'csrfmiddlewaretoken': csrftoken,
                    }, function(data) {
			$("#pendingwarning").remove();
                    });
    });


    var filter_task = document.getElementById("filter_tasks");
    if (filter_task) {
        filter_task.addEventListener("keyup", delaySearch(function(event) {
            searchTasks(event);	    
        },1000));
    }

    $("#filterstatus").change(function(event) {
        searchTasks(event);
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


    
    
});
