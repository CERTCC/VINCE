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


function nextPage(page) {
    var url = $("#searchform").attr("action");
    var facet = $(".search-menu .menu li .menu-active").text();
    $("#searchresults").load(url+"?page=" + page + "&facet=" + facet);
}

function nextResults(page) {
    var url = $("#searchform").attr("action");
    var facet = $(".search-menu .menu li .menu-active").text();
    $("#id_page").val(page);
    var data = $('#searchform').serialize() + "&facet=" + facet;
    $.ajax({
        url: url,
        type: "GET",
        data: data,
        success: function(data) {
            $("#searchresults").html(data);
        }
    });

}

var priorSearchReq = null;

function searchContacts() {
    var url = $("#searchform").attr("action");
    $("#loader").replaceWith("<div class='loading_gif'></div>");
    $("#id_page").val("1");
    var facet = $(".search-menu .menu li .menu-active").text();
    if (history.pushState) {
        var newurl = window.location.protocol + "//" + window.location.host + window.location.pathname + '?q=' + $("#search_vector").val() + "&facet=" + facet;
        window.history.pushState({path:newurl},'',newurl);
    }
    var data = $('#searchform').serialize() + "&facet=" + facet;
    if(priorSearchReq) {
        priorSearchReq.abort();
    }
    priorSearchReq = $.ajax({
	url: url,
	type: "GET",
	data: data,
	success: function(data) {
	    $("#searchresults").html(data);
	    $(document).foundation();
	    priorSearchReq = null;
	}
    });
}


$(document).ready(function() {


    $(document).on("click", '.search_page', function(event) {
        var page = $(this).attr('next');
        nextPage(page);
    });

    $(document).on("click", '.search_notes', function(event) {
        var page = $(this).attr('next');
        nextResults(page);
    });

    searchContacts();

    $(".search-menu .menu li").on("click", "a", function(event) {
        $( ".search-menu .menu li" ).each(function( index ) {
            $(this).children().removeClass("menu-active");
        });
        $(this).toggleClass("menu-active");
	event.preventDefault();
        searchContacts();

    });
    
    $(document).on("click", '#reassign', function(event) {
        $("#assign_block").show();
        $(".assigned_to").hide();

    });

    $(document).on("click", "#assign_submit", function(event) {
        var val = $("#uassign option:selected").val()
        window.location.href="?assign="+val;
        $("#assign_block").hide();
        $(".assigned_to").show();
	location.reload(true);
    });

    $(document).on("click", "#assign_cancel", function(event) {
        $("#assign_block").hide();
        $(".assigned_to").show();
    });

    $(document).on("change", 'input[type=radio][name=sort]', function(event) {
	searchContacts();

    });
    

    var input = document.getElementById("search_vector");
    if (input) {
	input.addEventListener("keyup", function(event) {
            searchContacts();
	});
    }

    $(document).on("submit", "#searchform", function(event) {
	event.preventDefault();
	searchContacts();
    });

    

});
