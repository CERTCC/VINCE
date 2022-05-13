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


$(document).ready(function() {

    var addmodal = $("#modal");
    
    $(document).on("click", '.approve', function(event) {
	event.preventDefault();
        var csrftoken = getCookie('csrftoken');
        var url = $(this).attr("href");
	var addurl = $(this).attr("action");
	
        $.post(url, {'csrfmiddlewaretoken': csrftoken, 
                    }, function(data) {
			$("#user-list").html(data);
			/*$.ajax({
			    url: addurl,
			    type: "GET",
			    success: function(data) {
				addmodal.html(data).foundation('open');
			    }
			});*/
                    })
	    .fail(function(d) {
		addmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: You are not permitted to perform this action</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');

            });

    });

    
    $(document).on("click", '.remove', function(event) {
	event.preventDefault();
	var url = $(this).attr("href");

        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		addmodal.html(data).foundation('open');
	    },
	    error: function(xhr, status) {
		addmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: You are not permitted to perform this action</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
	    }
	});
	    
    });


    $.widget("custom.tablecomplete", $.ui.autocomplete, {
        _create: function() {
            this._super();
            this.widget().menu("option", "items", "> tr:not(.ui-autocomplete-header)");
        },
        _renderMenu(ul, items) {
            var self = this;
            //table definitions                                                                      
            var $t = $("<table class=\"unstriped hover\">", {
                border: 1
            }).appendTo(ul);
            $t.append($("<thead>"));
            $t.find("thead").append($("<tr>", {
                class: "ui-autocomplete-header"
            }));
            var $row = $t.find("tr");
            $("<th>").html("Name").appendTo($row);
            $("<tbody>").appendTo($t);
            $.each(items, function(index, item) {
                self._renderItemData(ul, $t.find("tbody"), item);
            });
        },
        _renderItemData(ul, table, item) {
            return this._renderItem(table, item).data("ui-autocomplete-item", item);
        },
        _renderItem(table, item) {
            var $row = $("<tr>", {
                class: "ui-menu-item",
                role: "presentation"
            })
            $("<td>").html(item.value).appendTo($row);
            return $row.appendTo(table);
        }
    });
    

    function _doFocusStuff(event, ui) {
        if (ui.item) {
            console.log(ui.item);
            var $item = ui.item;
            $("#id_contact").val($item.value);
            /*$("#project-description").html($item.value);*/
        }
        return false;
    }

    function _doSelectStuff(event, ui) {
        if (ui.item) {
            var $item = ui.item;
            renderTable("#project-description", $item);
            $("#id_contact").val('');
            $("#id_contact").focus();
        }
        return false;
    }


    function vend_auto(data) {
	var autocomplete = $("#id_contact").tablecomplete({
            minLength: 1,
            source: data,
            focus: _doFocusStuff,
            select: _doSelectStuff
	    
	});
    }
    
    function renderTable(p, item) {
        var self = this;
        //table definitions                                                                          
        var $row = $("<tr>", {
            class: "ui-menu-item",
            role: "presentation"
        })
        $("<td>").html(item.value).appendTo($row);
        $row.appendTo(p)
    }

    var vendorinput = document.getElementById("id_contact");
    if (vendorinput) {
	vendorinput.addEventListener("keydown", function(event) {
            if (event.keyCode == 13) {
                event.preventDefault();
	        renderTable("#project-description", {value:$("#id_contact").val(), label:$("#id_contact").val()});
                $("#id_contact").val('');
                $("#id_contact").focus();
	    }
        });
    }

     $.getJSON("/vince/api/vendors/", function(data) {
         vend_auto(data);
     });


    $(document).on("submit", '#addusercontact', function(event) {
        event.preventDefault();
        var vendors = [];
        var csrftoken = getCookie('csrftoken');
	var rows = $("#project-description > tr");

        $.each(rows, function(index, item) {
            vendors.push(item.cells[0].innerText);
	});
        var url = $(this).attr("action");

        $.post(url, {'csrfmiddlewaretoken': csrftoken, 'vendors': vendors,
                    })
	    .done(function(data, textStatus, jqXHR) {
                        /*remove rows in table */
			window.location=data['url'];
            });

    });
    
    
});
