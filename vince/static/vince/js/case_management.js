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

function loadEditForm(id, panel) {
    var url = "/vince/case_template/edit/"+id+"/";
    $.ajax({
	url: url,
	success: function(data) {
	    $(panel).html(data);
	}
    });
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
function searchTmpls(e, table) {
    var csrftoken = getCookie('csrftoken');

    if (e) {
        e.preventDefault();
    }

    var url = $("#filter_templates").attr("href");
    var owner = $("input[id^='id_owner_']:checked").val();
    lockunlock(true,'div.vtmainbody,div.mainboxy','#' + table.id);
    window.txhr = $.ajax({
        url : url,
        type: "POST",
        data: {"keyword": $("#filter_templates").val(),
               "owner": owner,
               "csrfmiddlewaretoken": csrftoken
              },
        success: function(data) {
	    lockunlock(false,'div.vtmainbody,div.mainbody','#' + table.id);
	    table.replaceData(data['templates'])
        },
        error: function() {
	    lockunlock(false,'div.vtmainbody,div.mainbody','#' + table.id);
            console.log(arguments);
            alert("Search failed or canceled! See console log for details.");
        },
        complete: function() {
            /* Just safety net */
	    lockunlock(false,'div.vtmainbody,div.mainbody','#' + table.id);
            window.txhr = null;
        }	
    });
}



$(document).ready(function() {

    var filter_msg = document.getElementById("filter_templates");
    if (filter_msg) {
        filter_msg.addEventListener("keyup", delaySearch(function(event) {
            searchTmpls(event, table);
        },1000));
    }

    $("input[id^='id_owner_']").change(function() {
        searchTmpls(null, table);
    });

    $("#filter_by_dropdown_select_all_0").click(function(){
        $("input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchTmpls(null, table);

    });
    
    var addtask = $("#addtask");
    
    //define custom formatter function                                                            
    var tagFormatter = function(cell, formatterParams, onRendered){
        var values = cell.getValue();
        var tags = "";

        if(values){
            values.forEach(function(value){
                tags += "<span class='tag'>" + value + "</span>";
            });
        }
        return tags;
    };

    var buttonFormatter = function(cell,  formatterParams, onRendered){
	return "<a href=\"/vince/case_template/edit/"+cell.getValue()+"\" class=\"edittmpl btn-link\"><i class=\"fas fa-pencil-alt\"></i></a><button class=\"clonetmpl btn-link\" obj="+cell.getValue()+"><i class=\"far fa-clone\"></i></button><button class=\"deletetmpl btn-link\" obj="+cell.getValue()+"><i class=\"fas fa-trash-alt\"></i></button>";
    };

    if (document.getElementById('templates')) {
	var data = JSON.parse(document.getElementById('templates').textContent);
    }
    if (document.getElementById('tasks')) {
	var tasks = JSON.parse(document.getElementById('tasks').textContent);
    }

    var cellClickFunction = function(e, cell) {
	var url_mask = "/vince/case_template/edit/" + cell.getRow().getData().id;
        window.location = url_mask;
    };
    
   if (data) {
	var table = new Tabulator("#template-table", {
        data:data, //set initial table data          
            layout:"fitColumns",
            columns:[
		{title:"Title", field:"title", cellClick: cellClickFunction},
		{title:"Description", field:"description", cellClick: cellClickFunction},
		{title:"Date Modified", field:"date", cellClick: cellClickFunction},
		{title:"Added By", field:"user", cellClick: cellClickFunction},
		{title:"Tasks", field:"tasks", width:100, cellClick: cellClickFunction},
		{formatter:buttonFormatter, align:"center", width:100, field:"id"}
            ],
	    
	});
   }

    var taskbuttonFormatter = function(cell,  formatterParams, onRendered){
	
	return "<button class=\"edittask btn-link\" obj="+cell.getValue()+"><i class=\"fas fa-pencil-alt\"></i></a><button class=\"clonetask btn-link\" obj="+cell.getValue()+"><i class=\"far fa-clone\"></i></button><button class=\"deletetask btn-link\" obj="+cell.getValue()+"><i class=\"fas fa-trash-alt\"></i></button>";
    };
    
    if (tasks) {
	var task_table = new Tabulator("#task-table", {
            data:tasks, //set initial table data
            placeholder:"There are no tasks for this template.",
            layout:"fitColumns",
            columns:[
		{title:"Title", field:"title", width:250},
		{title:"Description", field:"description", width:250},
		{title:"Priority", field:"priority", width:90, align:"center"},
		{title:"Assigned To", field:"user"},
		{title:"Time to Complete", field:"time"},
		{title:"Dependency", field:"dependency", width:100},
		{formatter:taskbuttonFormatter, align:"center", field:"id"}
            ],
	});
    }

    $(document).on("click", ".edittask", function(event) {
	event.preventDefault();
	var url = "/vince/case_template/task/edit/" + $(this).attr("obj");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                addtask.html(data).foundation('open');
            }
        });
    });

    $(document).on("click", ".deletetask", function(event) {
        event.preventDefault();
	var obj = $(this).attr("obj");
        $.ajax({
            url: "/vince/case_template/task/delete/"+obj,
            type: "GET",
            success: function(data) {
		$("#deletetask").html(data).foundation('open');
            }
        });
	
    });

    
    $(document).on("click", ".task-dropdown", function(event) {
	event.preventDefault();
	$(this).next('.task-description').show();
	$(this).next('.task-description').slideDown();
	$(this).replaceWith('<a href="#" class="task-up"><i class="fas fa-caret-up"></i></a>');
	
    });
    $(document).on("click", ".cancelform", function(event) {
	location.reload();
    });
    
    $(document).on("click", ".task-up", function(event) {
	event.preventDefault();
	$(this).next('.task-description').hide();
        $(this).next('.task-description').slideUp();
	$(this).replaceWith('<a href="#" class="task-dropdown"><i class="fas fa-caret-down"></i></a>');
    });
    
    var addmodal = $("#add_case_template");

    $(document).on("click", "#new_template", function(event) {
	event.preventDefault();
	$.ajax({
            url: $(this).attr("action"),
            type: "GET",
            success: function(data) {
		addmodal.html(data).foundation('open');
	    }
	});
    });


    $(document).on("click", "#add_task", function(event) {
        event.preventDefault();
	var url = $(this).attr("action");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                addtask.html(data).foundation('open');
            }
        });
    });

    $(document).on('click', '#submitaddtask',  function(event) {
	event.preventDefault();
	var formdata = $('#addtaskForm').serializeArray();
	$.post($("#addtaskForm").attr("action"), formdata,
               function(data) {
		   task_table.replaceData(data['tasks']);
               })
	    .done(function() {
		addtask.foundation('close');
	    });
    });

    var deletemodal = $("#delete_template");
    $(document).on('click', '.deletetmpl', function(event) {
	event.preventDefault();
	var obj = $(this).attr("obj");
	$.ajax({
            url: "/vince/case_template/delete/"+obj,
            type: "GET",
            success: function(data) {
                deletemodal.html(data).foundation('open');
            }
        });
    });

    $(document).on('click', '.clonetmpl', function(event) {
	event.preventDefault();
	var obj = $(this).attr("obj");
        $.ajax({
            url: "/vince/case_template/clone/"+obj+"/",
            type: "GET",
            success: function(data) {
		window.location = data['url'];
            }
        });
    });

    $(document).on('click', '.clonetask', function(event) {
        event.preventDefault();
	var obj = $(this).attr("obj");
        $.ajax({
            url: "/vince/case_template/task/clone/"+obj+"/",
            type: "GET",
	    success: function(data) {
		addtask.html(data).foundation('open');
            }
	});
    });
    
});
	    
