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



function init_tags() {
    var artifact_tags = []
    if (document.getElementById('artifact_tags')) {
	artifact_tags =	JSON.parse(document.getElementById('artifact_tags').textContent);
    }
    
    var taggle = new Taggle('taggs', {
	tags: artifact_tags,
	duplicateTagClass: 'bounce',
	placeholder: ["Tag this artifact..."],
	
    });

    autoTaggle($("#taggs").attr("href"), taggle);
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
            }
        }
    });
}  


$(document).ready(function() {

    
    var data = JSON.parse(document.getElementById('artifacts').textContent);

    var tableData = [
	{id:1, name:"Billy Bob", age:"12", gender:"male", height:1, col:"red", dob:"", cheese:1},
	{id:2, name:"Mary May", age:"1", gender:"female", height:2, col:"blue", dob:"14/05/1982", cheese:true},
    ]

    var linkFormatter = function(cell, formatterParams, onRendered) {
	var values = cell.getValue();
	if (cell.getRow().getData().url) {
	    return "<a href=\""+cell.getRow().getData().url+"\" target=\"_blank\">"+cell.getRow().getData().value+"</a>";
	}
	else {
	    return values;
	}
    }

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
    }


    var taskbuttonFormatter = function(cell,  formatterParams, onRendered){
        var buttons = "<button class=\"editartifact btn-link\" obj="+cell.getValue()+"><i class=\"fas fa-pencil-alt\"></i></a>";
	if (cell.getRow().getData().url) {
	    if (cell.getRow().getData().public) {
		buttons = buttons + "<button class=\"shareartifact btn-link\" href="+cell.getRow().getData().share_url+"><i class=\"fas fa-unlink\"></i></button>";
	    } else {
		buttons = buttons + "<button class=\"shareartifact btn-link\" pub=1 href="+cell.getRow().getData().share_url+"><i class=\"fas fa-share-square\"></i></button>";
	    }
	}
	buttons = buttons + "<button class=\"deleteartifact btn-link\" href="+cell.getRow().getData().delete_url+"><i class=\"fas fa-trash-alt\"></i></button>";
	return buttons;
    };

    var modal = $("#editartifact");

    var cellClickFunction = function(e, cell) {
	var url = "/vince/artifact/"+ cell.getRow().getData().id + "/edit/"
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
                init_tags();
            },
	    error: function(xhr, status) {
                permissionDenied(modal);
            }
	    
        });
    }
    
    var table = new Tabulator("#artifact-table", {
	data:data, //set initial table data
	layout:"fitColumns",
	height: "250px",
	placeholder: "There are no artifacts for this case.",
	columns:[
            {title:"Type", field:"type", cellClick:cellClickFunction},
            {title:"Title", field:"title", cellClick:cellClickFunction},
	    {title:"Ticket", field:"ticket_url", formatter:"link", formatterParams: {urlField:"related_ticket", url:function(cell) {return cell.getRow().getData().related_ticket; }}},
            {title:"Value", field:"value", formatter:linkFormatter},
            {title:"Description", field:"description", cellClick:cellClickFunction},
            {title:"Date Added", field:"date_added", cellClick:cellClickFunction},
            {title:"Added By", field:"user", cellClick:cellClickFunction},
	    {title:"Tags", field:"tags", formatter:tagFormatter, width:250, cellClick:cellClickFunction},
	    {formatter:taskbuttonFormatter, align:"center", field:"id"}
	],
	
    });

    $(document).on("click", ".shareartifact", function(event) {
        event.preventDefault();
	var url = $(this).attr("href");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
            },
	    error: function(xhr, status) {
                permissionDenied(modal);
            }
        });
    });

    $(document).on("click", ".deleteartifact", function(event) {
        event.preventDefault();
        var url = $(this).attr("href");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
            },
	    error: function(xhr, status) {
                permissionDenied(modal);
            }
        });
    });

    
    $(document).on('submit', '#editartifactform',  function(event) {
        event.preventDefault();
        var formdata = $(this).serializeArray();
        $.post($(this).attr("action"), formdata,
               function(data) {
                   table.replaceData(data['artifacts']);
		   modal.foundation('close');
               })
	    .fail(function() {
		permissionDenied(modal);
	    });
    });
		 

    
    $(document).on("click", ".editartifact", function(event) {
        event.preventDefault();
        var url = "/vince/artifact/"+ $(this).attr("obj") + "/edit/"
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
		init_tags();
            },
	    error: function(xhr, status) {
                permissionDenied(modal);
            }
        });
    });

    $(document).on("click", "#addartifact", function(event) {
        event.preventDefault();
        var url = $(this).attr("action");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
                $("#id_comment").val($("#commentBox").val());
        		init_tags();
            },
	        error: function(xhr, status) {
                permissionDenied(modal);
            }
        });
    });

});
