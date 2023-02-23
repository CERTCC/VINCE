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

$(document).ready(function() {

    $(document).on("click", '#reassign', function(event) {
        $("#assign_block").show();
        $(".assigned_to").hide();

    });

    $(document).on("click", "#assign_submit", function(event) {
        var val = $("#uassign option:selected").val()
        window.location.href="?assign="+val;
        $("#assign_block").hide();
        $(".assigned_to").show();
    });

    $(document).on("click", "#assign_cancel", function(event) {
        $("#assign_block").hide();
        $(".assigned_to").show();
    });

    var containerEl = document.getElementById('external-events-list');
    new FullCalendar.Draggable(containerEl, {
	itemSelector: '.fc-event',
	eventData: function(eventEl) {
            return {
		title: eventEl.innerText.trim()
            }
	}
    });

    var addmodal = $("#modal");
    var rmmodal = $("#rmmodal");

    var calendarEl = document.getElementById('calendar');
    var calendar = new FullCalendar.Calendar(calendarEl, {
	events: '/vince/ajax_calls/calendar/events/',
	headerToolbar: {
            left: 'prev,next today',
            center: 'title',
            right: 'dayGridMonth,timeGridWeek,timeGridDay,listWeek'
	},
	navLinks: true, // can click day/week names to navigate views
	selectable: true,
	selectMirror: true,
	select: function(arg) {
	    var csrftoken = getCookie('csrftoken');
	    $.ajax({
		url: addmodal.attr("href"),
		type: "POST",
		data: {'csrfmiddlewaretoken': csrftoken, 'arg': arg.startStr},
		success: function(data) {
                    addmodal.html(data).foundation('open');
		}
            });
            calendar.unselect()
	},
	eventClick: function(arg) {
	    var csrftoken = getCookie('csrftoken');
	    $.ajax({
                url: rmmodal.attr("href"),
                type: "POST",
                data: {'csrfmiddlewaretoken': csrftoken, 'arg': arg.event.id},
                success: function(data) {
                    rmmodal.html(data).foundation('open');
                }
            });
	},
	eventChange: function(arg) {
	    var csrftoken = getCookie('csrftoken');
            $.ajax({
                url: addmodal.attr("href"),
                type: "POST",
                data: {'csrfmiddlewaretoken': csrftoken, 'newend': arg.event.endStr,
		       'event_id': arg.event.id},
                success: function(data) {
                }
            });
            calendar.unselect()
	},
	eventReceive: function(arg) {
	    var csrftoken = getCookie('csrftoken');
	    var objname = arg.draggedEl.getAttribute('class');
	    var event_id = '1';
	    if (objname.includes('oof')) {
		event_id = '2';
	    }
	    $.ajax({
		url: addmodal.attr("href"),
		type: "POST",
		data: {'csrfmiddlewaretoken': csrftoken,
		       'event_id': event_id,
		       'date': arg.event.startStr},
		success: function(data) {
		    addmodal.foundation('close');
		    if (data["title"]) {
			calendar.addEvent({
			    title: data['title'],
			    start: data['date'],
			    id: data['id'],
			    className: data['className'],
			    end: data['date'],
			    allDay: true
			})
		    }
		    arg.event.remove();
		},
		error: function(xhr, status) {
		    var data = JSON.parse(xhr.responseText);
                    rmmodal.foundation('close');
                    rmmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+data['error']+"</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
		    arg.event.remove();
		}
	    });
	},
	editable: true,
	eventStartEditable: false,
	eventResizableFromStart: false,
	eventDurationEditable: true,
	droppable:true,
    });
    calendar.render();

    $(document).on("submit", '#rmeventform', function(event) {
	event.preventDefault();
        $.ajax({
            url: $(this).attr("action"),
            type: "POST",
            data: $(this).serialize(),
            success: function(data) {
		rmmodal.foundation('close');
		event = calendar.getEventById(data['event']);
		event.remove();
	    },
	    error: function(xhr, status) {
		var data = JSON.parse(xhr.responseText);
		rmmodal.foundation('close');
		rmmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+data['error']+"</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
	    }
	});
    });

    
    $(document).on("submit", '#eventform', function(event) {
        event.preventDefault();
	$.ajax({
            url: $(this).attr("action"),
            type: "POST",
            data: $(this).serialize(),
            success: function(data) {
                addmodal.foundation('close');
		if (data["title"]) {
                    calendar.addEvent({
			title: data['title'],
			start: data['date'],
			id: data['id'],
			end: data['date'],
			allDay: true
                    })
		}
		calendar.unselect();
	    }
        });
    });

});
