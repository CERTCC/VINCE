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
/*
       Licensed to the Apache Software Foundation (ASF) under one
       or more contributor license agreements.  See the NOTICE file
       distributed with this work for additional information
       regarding copyright ownership.  The ASF licenses this file
       to you under the Apache License, Version 2.0 (the
       "License"); you may not use this file except in compliance
       with the License.  You may obtain a copy of the License at
         http://www.apache.org/licenses/LICENSE-2.0
       Unless required by applicable law or agreed to in writing,
       software distributed under the License is distributed on an
       "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
       KIND, either express or implied.  See the License for the
       specific language governing permissions and limitations
       under the License.
*/

/* revised from Apache Allura project */

var userMentionList;

$(function() {
    var data = "";
    $.ajax({
        url: $("#loadmembers").attr('href'),
        type: "GET",
        success: function(resp) {
	    data = resp;
	    userMentionList = data.map(function(item) {
		return {
		    text: item.value,
		    displayText: item.label
		};
	    });
        }
    });
    
    /*var data = JSON.parse(document.getElementById('members').textContent);*/

});

CodeMirror.registerHelper('hint', 'alluraUserMentions', function (editor) {
    var word = /[^@]+/;
    var cur = editor.getCursor(), curLine = editor.getLine(cur.line);
    var tokenType = editor.getTokenTypeAt(cur);

    if(!!tokenType && tokenType.indexOf('comment') != -1) // Disable um inside code
	return;

    var end = cur.ch, start = end;
    // Find the starting position of currently typed word and set it to 'start' var
    while (start && word.test(curLine.charAt(start - 1))) --start;
    // Extract the current word from the current line using 'start' / 'end' value pair
    var curWord = start != end && curLine.slice(start, end);
    var list = [];
    if(curWord) {
	// If there is current word set, We can filter out users from the main list and display them
	userMentionList.forEach(function(item) {
	    if(item.displayText.toLowerCase().indexOf(curWord.toLowerCase()) != -1)
		list.push(item);
	});
    }
    else {
	// Otherwise, we display the entire list
	list = userMentionList.slice();
    }

    return { list: list, from: CodeMirror.Pos(cur.line, start), to: CodeMirror.Pos(cur.line, end) };
});
