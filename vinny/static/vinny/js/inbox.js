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

function fload(fdiv,furl,fmethod) {
    lockunlock(true,'div.mainbody,div.vtmainbody',fdiv);
    window.txhr = $.ajax({
	url : furl,
        type: fmethod,
	data: fmethod == "POST" ? $('#filterform').serialize() : null,
	success: function(data) {
	    lockunlock(false,'div.mainbody,div.vtmainbody','#inbox');
            $(fdiv).html(data);
	},
       error: function() {
           lockunlock(false,'div.mainbody,div.vtmainbody','#inbox');      
           console.log(arguments);
           alert("Search failed or canceled! See console log for details.");
       },
       complete: function() {
           /* Just safety net */
           lockunlock(false,'div.mainbody,div.vtmainbody','#inbox');      
           window.txhr = null;
       }
    });
}

function nextPage(page) {
    var url = $("#filterform").attr("action") + "?page=" + page;
    fload('#inbox',url,"GET");
}

function nextThreads(page) {
    $("#id_page").val(page);
    var url = $("#filterform").attr("action");
    fload('#inbox',url,"POST");
}

function searchThreads(e) {
    if (e) {
        e.preventDefault();
    }
    $("#id_page").val("1");
    var url = $("#filterform").attr("action");
    fload('#inbox',url,"POST");
}

function nextSent(page) {
    var url = $("#filterform").attr("action") + "?page=" + page;
    fload('#sent',url,"GET");
}
function async_load() {
    /* Async loading of inbox and sent items */
    nextThreads(1);
    /* Load nextSent only on tab click 
       nextSent(1);
    */
}


$(document).ready(function() {
    /* Async loading of inbox and sent items */
    async_load();
    $('#sent-label').on("click", function() {
	if($('#sent div').length < 1)
	    nextSent(1);
    });
    $(document).on("click", '.search_page', function(event) {
        var page = $(this).attr('next');
        nextPage(page);
    });

    $(document).on("click", '.search_notes', function(event) {
        var page = $(this).attr('next');
	event.preventDefault();
        nextThreads(page);
    });

    $(document).on("click", '.searchsent', function(event) {
        var page = $(this).attr('next');
        event.preventDefault();
        nextSent(page);
    });

    
    var filter_msg = document.getElementById("id_keyword");
    if (filter_msg) {
	filter_msg.addEventListener("keyup", delaySearch(function(event) {
             searchThreads(event);
        },1000));
    }

    var modal = $("#deletemodal");

    $(document).on("click", ".delete-btn", function(event) {
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

    $(document).on("submit", "#filterform", function(event) {
	event.preventDefault();
	searchThreads();
    });
	
    
    $("input[id^='id_status_']").change(function() {
	searchThreads();
    });

    $("#filter_by_dropdown_select_all_0").click(function(){
	$("input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchThreads();

    });
    
});
