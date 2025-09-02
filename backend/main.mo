import AccessControl "authorization/access-control";
import Registry "blob-storage/registry";
import Principal "mo:base/Principal";
import OrderedMap "mo:base/OrderedMap";
import Time "mo:base/Time";
import Array "mo:base/Array";
import Text "mo:base/Text";
import List "mo:base/List";
import Debug "mo:base/Debug";
import Int "mo:base/Int";
import Nat "mo:base/Nat";
import Iter "mo:base/Iter";
import UserApproval "user-approval/approval";

persistent actor {
    // Access control state
    let accessControlState = AccessControl.initState();

    // File registry
    let registry = Registry.new();

    // User approval state
    let approvalState = UserApproval.initState(accessControlState);

    // User profile type
    public type UserProfile = {
        displayName : Text;
        avatarPath : ?Text;
        email : ?Text;
        phoneNumber : ?Text;
    };

    // Club type
    public type Club = {
        id : Text;
        name : Text;
        description : Text;
        owner : Principal;
        created : Time.Time;
    };

    // Team type
    public type Team = {
        id : Text;
        clubId : Text;
        name : Text;
        description : Text;
        owner : Principal;
        created : Time.Time;
    };

    // Membership type
    public type Membership = {
        userId : Principal;
        teamId : Text;
        role : Text;
    };

    // Message type
    public type Message = {
        id : Text;
        threadId : Text;
        sender : Principal;
        content : Text;
        timestamp : Time.Time;
    };

    // Chat thread type
    public type ChatThread = {
        id : Text;
        name : Text;
        participants : [Principal];
        created : Time.Time;
        clubId : ?Text;
        teamId : ?Text;
        requiredRole : ?Text;
        isAllRoles : Bool;
    };

    // Child profile type
    public type ChildProfile = {
        name : Text;
        dateOfBirth : Text;
        parent : Principal;
    };

    // Notification type
    public type Notification = {
        id : Text;
        recipient : Principal;
        notificationType : Text;
        content : Text;
        timestamp : Time.Time;
        isRead : Bool;
        relatedId : ?Text;
        sender : ?Principal;
    };

    // Event type
    public type Event = {
        id : Text;
        title : Text;
        description : Text;
        date : Time.Time;
        clubId : ?Text;
        teamId : ?Text;
        createdBy : Principal;
        eventType : Text;
        invitedMembers : [Principal];
    };

    // RSVP type
    public type RSVP = {
        eventId : Text;
        userId : Principal;
        status : Text;
        timestamp : Time.Time;
        childName : ?Text;
    };

    // Initialize OrderedMap operations
    transient let principalMap = OrderedMap.Make<Principal>(Principal.compare);
    transient let textMap = OrderedMap.Make<Text>(Text.compare);

    // Storage
    var userProfiles : OrderedMap.Map<Principal, UserProfile> = principalMap.empty();
    var clubs : OrderedMap.Map<Text, Club> = textMap.empty();
    var teams : OrderedMap.Map<Text, Team> = textMap.empty();
    var memberships : OrderedMap.Map<Text, Membership> = textMap.empty();
    var messages : OrderedMap.Map<Text, Message> = textMap.empty();
    var chatThreads : OrderedMap.Map<Text, ChatThread> = textMap.empty();
    var childProfiles : OrderedMap.Map<Principal, ChildProfile> = principalMap.empty();
    var childMemberships : OrderedMap.Map<Text, Text> = textMap.empty();
    var notifications : OrderedMap.Map<Text, Notification> = textMap.empty();
    var events : OrderedMap.Map<Text, Event> = textMap.empty();
    var rsvps : OrderedMap.Map<Text, RSVP> = textMap.empty();

    // Access control functions
    public shared ({ caller }) func initializeAccessControl() : async () {
        AccessControl.initialize(accessControlState, caller);
    };

    public query ({ caller }) func getCallerUserRole() : async AccessControl.UserRole {
        AccessControl.getUserRole(accessControlState, caller);
    };

    public shared ({ caller }) func assignCallerUserRole(user : Principal, role : AccessControl.UserRole) : async () {
        AccessControl.assignRole(accessControlState, caller, user, role);
    };

    public query ({ caller }) func isCallerAdmin() : async Bool {
        AccessControl.isAdmin(accessControlState, caller);
    };

    // User approval functions
    public query ({ caller }) func isCallerApproved() : async Bool {
        AccessControl.hasPermission(accessControlState, caller, #admin) or UserApproval.isApproved(approvalState, caller);
    };

    public shared ({ caller }) func setApproval(user : Principal, status : UserApproval.ApprovalStatus) : async () {
        if (not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
            Debug.trap("Unauthorized: Only admins can perform this action");
        };
        UserApproval.setApproval(approvalState, user, status);
    };

    public query ({ caller }) func listApprovals() : async [UserApproval.UserApprovalInfo] {
        if (not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
            Debug.trap("Unauthorized: Only admins can perform this action");
        };
        UserApproval.listApprovals(approvalState);
    };

    // User profile functions
    public query ({ caller }) func getCallerUserProfile() : async ?UserProfile {
        principalMap.get(userProfiles, caller);
    };

    public query func getUserProfile(user : Principal) : async ?UserProfile {
        principalMap.get(userProfiles, user);
    };

    public shared ({ caller }) func saveCallerUserProfile(profile : UserProfile) : async () {
        userProfiles := principalMap.put(userProfiles, caller, profile);
    };

    // File registry functions
    public func registerFileReference(path : Text, hash : Text) : async () {
        Registry.add(registry, path, hash);
    };

    public query func getFileReference(path : Text) : async Registry.FileReference {
        Registry.get(registry, path);
    };

    public query func listFileReferences() : async [Registry.FileReference] {
        Registry.list(registry);
    };

    public func dropFileReference(path : Text) : async () {
        Registry.remove(registry, path);
    };

    // Club management functions
    public shared ({ caller }) func createClub(name : Text, description : Text) : async Text {
        if (Principal.isAnonymous(caller)) {
            Debug.trap("Anonymous users cannot create clubs");
        };

        let clubId = Principal.toText(caller) # "-" # name;
        let newClub : Club = {
            id = clubId;
            name = name;
            description = description;
            owner = caller;
            created = Time.now();
        };

        clubs := textMap.put(clubs, clubId, newClub);

        // Create chat thread for club
        let threadId = clubId # "-thread";
        let clubThread : ChatThread = {
            id = threadId;
            name = name # " Club Chat";
            participants = [caller];
            created = Time.now();
            clubId = ?clubId;
            teamId = null;
            requiredRole = null;
            isAllRoles = true;
        };
        chatThreads := textMap.put(chatThreads, threadId, clubThread);

        clubId;
    };

    public query func getClub(clubId : Text) : async ?Club {
        textMap.get(clubs, clubId);
    };

    public shared ({ caller }) func deleteClub(clubId : Text, confirm : Bool) : async () {
        if (not confirm) {
            Debug.trap("Deletion not confirmed");
        };

        switch (textMap.get(clubs, clubId)) {
            case null { Debug.trap("Club not found") };
            case (?club) {
                // Check if caller has club_admin role for this club
                var isClubAdmin = false;
                for ((_, membership) in textMap.entries(memberships)) {
                    if (membership.userId == caller and membership.role == "club_admin") {
                        switch (textMap.get(teams, membership.teamId)) {
                            case null {};
                            case (?team) {
                                if (team.clubId == clubId) {
                                    isClubAdmin := true;
                                };
                            };
                        };
                    };
                };

                if (not isClubAdmin) {
                    Debug.trap("Only club admins can delete the club");
                };

                // Delete associated teams
                for ((teamId, team) in textMap.entries(teams)) {
                    if (team.clubId == clubId) {
                        teams := textMap.delete(teams, teamId);
                    };
                };

                // Delete associated memberships
                for ((membershipId, membership) in textMap.entries(memberships)) {
                    if (membership.teamId == clubId) {
                        memberships := textMap.delete(memberships, membershipId);
                    };
                };

                // Delete associated chat threads
                for ((threadId, thread) in textMap.entries(chatThreads)) {
                    if (Text.contains(thread.id, #text clubId)) {
                        chatThreads := textMap.delete(chatThreads, threadId);
                    };
                };

                // Delete the club
                clubs := textMap.delete(clubs, clubId);
            };
        };
    };

    // New function to update a club
    public shared ({ caller }) func updateClub(clubId : Text, name : Text, description : Text) : async () {
        switch (textMap.get(clubs, clubId)) {
            case null { Debug.trap("Club not found") };
            case (?club) {
                // Check if caller has club_admin role for this club
                var isClubAdmin = false;
                for ((_, membership) in textMap.entries(memberships)) {
                    if (membership.userId == caller and membership.role == "club_admin") {
                        switch (textMap.get(teams, membership.teamId)) {
                            case null {};
                            case (?team) {
                                if (team.clubId == clubId) {
                                    isClubAdmin := true;
                                };
                            };
                        };
                    };
                };

                if (not isClubAdmin) {
                    Debug.trap("Only club admins can update the club");
                };

                let updatedClub : Club = {
                    id = clubId;
                    name = name;
                    description = description;
                    owner = club.owner;
                    created = club.created;
                };

                clubs := textMap.put(clubs, clubId, updatedClub);
            };
        };
    };

    // Team management functions
    public shared ({ caller }) func createTeam(clubId : Text, name : Text, description : Text) : async Text {
        if (Principal.isAnonymous(caller)) {
            Debug.trap("Anonymous users cannot create teams");
        };

        switch (textMap.get(clubs, clubId)) {
            case null { Debug.trap("Club not found") };
            case (?club) {
                if (club.owner != caller and not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
                    Debug.trap("Only club owner or admin can create teams");
                };

                let teamId = clubId # "-" # name;
                let newTeam : Team = {
                    id = teamId;
                    clubId = clubId;
                    name = name;
                    description = description;
                    owner = caller;
                    created = Time.now();
                };

                teams := textMap.put(teams, teamId, newTeam);

                // Create chat thread for team
                let threadId = teamId # "-thread";
                let teamThread : ChatThread = {
                    id = threadId;
                    name = name # " Team Chat";
                    participants = [caller];
                    created = Time.now();
                    clubId = ?clubId;
                    teamId = ?teamId;
                    requiredRole = null;
                    isAllRoles = true;
                };
                chatThreads := textMap.put(chatThreads, threadId, teamThread);

                teamId;
            };
        };
    };

    public query func getTeam(teamId : Text) : async ?Team {
        textMap.get(teams, teamId);
    };

    public shared ({ caller }) func deleteTeam(teamId : Text) : async () {
        switch (textMap.get(teams, teamId)) {
            case null { Debug.trap("Team not found") };
            case (?team) {
                // Check if caller has team_admin or club_admin role for this team
                var isAuthorized = false;
                for ((_, membership) in textMap.entries(memberships)) {
                    if (membership.userId == caller) {
                        if (membership.teamId == teamId and membership.role == "team_admin") {
                            isAuthorized := true;
                        } else if (membership.role == "club_admin") {
                            switch (textMap.get(teams, membership.teamId)) {
                                case null {};
                                case (?adminTeam) {
                                    if (adminTeam.clubId == team.clubId) {
                                        isAuthorized := true;
                                    };
                                };
                            };
                        };
                    };
                };

                if (not isAuthorized) {
                    Debug.trap("Only team admins or club admins can delete the team");
                };

                // Delete associated memberships
                for ((membershipId, membership) in textMap.entries(memberships)) {
                    if (membership.teamId == teamId) {
                        memberships := textMap.delete(memberships, membershipId);
                    };
                };

                // Delete associated chat threads
                for ((threadId, thread) in textMap.entries(chatThreads)) {
                    if (Text.contains(thread.id, #text teamId)) {
                        chatThreads := textMap.delete(chatThreads, threadId);
                    };
                };

                // Delete the team
                teams := textMap.delete(teams, teamId);
            };
        };
    };

    // New function to update a team
    public shared ({ caller }) func updateTeam(teamId : Text, name : Text, description : Text) : async () {
        switch (textMap.get(teams, teamId)) {
            case null { Debug.trap("Team not found") };
            case (?team) {
                // Check if caller has team_admin or club_admin role for this team
                var isAuthorized = false;
                for ((_, membership) in textMap.entries(memberships)) {
                    if (membership.userId == caller) {
                        if (membership.teamId == teamId and membership.role == "team_admin") {
                            isAuthorized := true;
                        } else if (membership.role == "club_admin") {
                            switch (textMap.get(teams, membership.teamId)) {
                                case null {};
                                case (?adminTeam) {
                                    if (adminTeam.clubId == team.clubId) {
                                        isAuthorized := true;
                                    };
                                };
                            };
                        };
                    };
                };

                if (not isAuthorized) {
                    Debug.trap("Only team admins or club admins can update the team");
                };

                let updatedTeam : Team = {
                    id = teamId;
                    clubId = team.clubId;
                    name = name;
                    description = description;
                    owner = team.owner;
                    created = team.created;
                };

                teams := textMap.put(teams, teamId, updatedTeam);
            };
        };
    };

    // Membership management functions
    public shared ({ caller }) func addMember(teamId : Text, userId : Principal, role : Text) : async () {
        switch (textMap.get(teams, teamId)) {
            case null { Debug.trap("Team not found") };
            case (?team) {
                if (team.owner != caller and not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
                    Debug.trap("Only team owner or admin can add members");
                };

                let membershipId = Principal.toText(userId) # "-" # teamId;
                let newMembership : Membership = {
                    userId = userId;
                    teamId = teamId;
                    role = role;
                };

                memberships := textMap.put(memberships, membershipId, newMembership);
            };
        };
    };

    public shared ({ caller }) func removeMember(teamId : Text, userId : Principal) : async () {
        switch (textMap.get(teams, teamId)) {
            case null { Debug.trap("Team not found") };
            case (?team) {
                if (team.owner != caller and not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
                    Debug.trap("Only team owner or admin can remove members");
                };

                let membershipId = Principal.toText(userId) # "-" # teamId;
                memberships := textMap.delete(memberships, membershipId);
            };
        };
    };

    public query func getTeamMembers(teamId : Text) : async [Membership] {
        var memberList = List.nil<Membership>();
        for ((_, membership) in textMap.entries(memberships)) {
            if (membership.teamId == teamId) {
                memberList := List.push(membership, memberList);
            };
        };
        List.toArray(memberList);
    };

    public query func getClubMembers(clubId : Text) : async [Membership] {
        var memberList = List.nil<Membership>();

        // Find all teams in the club
        for ((_, team) in textMap.entries(teams)) {
            if (team.clubId == clubId) {
                // Find all members of the team
                for ((_, membership) in textMap.entries(memberships)) {
                    if (membership.teamId == team.id) {
                        memberList := List.push(membership, memberList);
                    };
                };
            };
        };

        List.toArray(memberList);
    };

    // Messaging functions
    public shared ({ caller }) func sendMessage(threadId : Text, content : Text) : async Text {
        if (Principal.isAnonymous(caller)) {
            Debug.trap("Anonymous users cannot send messages");
        };

        switch (textMap.get(chatThreads, threadId)) {
            case null { Debug.trap("Chat thread not found") };
            case (?_) {
                let messageId = Principal.toText(caller) # "-" # Int.toText(Time.now());
                let newMessage : Message = {
                    id = messageId;
                    threadId = threadId;
                    sender = caller;
                    content = content;
                    timestamp = Time.now();
                };

                messages := textMap.put(messages, messageId, newMessage);
                messageId;
            };
        };
    };

    public query func getMessages(threadId : Text) : async [Message] {
        var messageList = List.nil<Message>();
        for ((_, message) in textMap.entries(messages)) {
            if (message.threadId == threadId) {
                messageList := List.push(message, messageList);
            };
        };
        List.toArray(messageList);
    };

    public shared ({ caller }) func createRoleSpecificChatThread(name : Text, clubId : Text, teamId : ?Text, role : ?Text, isAllRoles : Bool) : async Text {
        if (Principal.isAnonymous(caller)) {
            Debug.trap("Anonymous users cannot create chat threads");
        };

        // Check if caller is club owner
        var hasAdminRole = false;
        switch (textMap.get(clubs, clubId)) {
            case null {};
            case (?club) {
                if (club.owner == caller) {
                    hasAdminRole := true;
                };
            };
        };

        // If not club owner, check memberships
        if (not hasAdminRole) {
            for ((_, membership) in textMap.entries(memberships)) {
                if (membership.userId == caller) {
                    switch (teamId) {
                        case null {
                            // Check if user is club admin
                            if (membership.role == "club_admin") {
                                switch (textMap.get(teams, membership.teamId)) {
                                    case null {};
                                    case (?team) {
                                        if (team.clubId == clubId) {
                                            hasAdminRole := true;
                                        };
                                    };
                                };
                            };
                        };
                        case (?tid) {
                            if (membership.teamId == tid and (membership.role == "team_admin" or membership.role == "club_admin")) {
                                hasAdminRole := true;
                            };
                        };
                    };
                };
            };
        };

        if (not hasAdminRole) {
            Debug.trap("User must have admin role in the club or team to create chat thread");
        };

        let threadId = Principal.toText(caller) # "-" # name;
        let newThread : ChatThread = {
            id = threadId;
            name = name;
            participants = [caller];
            created = Time.now();
            clubId = ?clubId;
            teamId = teamId;
            requiredRole = role;
            isAllRoles = isAllRoles;
        };

        chatThreads := textMap.put(chatThreads, threadId, newThread);
        threadId;
    };

    public query func getChatThread(threadId : Text) : async ?ChatThread {
        textMap.get(chatThreads, threadId);
    };

    public query ({ caller }) func getAccessibleChatThreads() : async [ChatThread] {
        var accessibleThreads = List.nil<ChatThread>();

        // Get user's memberships
        var userMemberships = List.nil<Membership>();
        for ((_, membership) in textMap.entries(memberships)) {
            if (membership.userId == caller) {
                userMemberships := List.push(membership, userMemberships);
            };
        };

        // Check each thread for accessibility
        for ((_, thread) in textMap.entries(chatThreads)) {
            var hasAccess = false;

            // Check club threads
            switch (thread.clubId) {
                case null {};
                case (?clubId) {
                    for (membership in List.toIter(userMemberships)) {
                        switch (textMap.get(teams, membership.teamId)) {
                            case null {};
                            case (?team) {
                                if (team.clubId == clubId) {
                                    hasAccess := true;
                                };
                            };
                        };
                    };
                };
            };

            // Check team threads
            switch (thread.teamId) {
                case null {};
                case (?teamId) {
                    for (membership in List.toIter(userMemberships)) {
                        if (membership.teamId == teamId) {
                            hasAccess := true;
                        };
                    };
                };
            };

            // Check role-specific threads
            switch (thread.requiredRole) {
                case null {};
                case (?requiredRole) {
                    for (membership in List.toIter(userMemberships)) {
                        if (membership.role == requiredRole) {
                            switch (thread.teamId) {
                                case null {
                                    // Club-level role
                                    switch (thread.clubId) {
                                        case null {};
                                        case (?clubId) {
                                            switch (textMap.get(teams, membership.teamId)) {
                                                case null {};
                                                case (?team) {
                                                    if (team.clubId == clubId) {
                                                        hasAccess := true;
                                                    };
                                                };
                                            };
                                        };
                                    };
                                };
                                case (?teamId) {
                                    if (membership.teamId == teamId) {
                                        hasAccess := true;
                                    };
                                };
                            };
                        };
                    };
                };
            };

            // Check all roles threads
            if (thread.isAllRoles) {
                switch (thread.teamId) {
                    case null {
                        // Club-level all roles thread
                        switch (thread.clubId) {
                            case null {};
                            case (?clubId) {
                                for (membership in List.toIter(userMemberships)) {
                                    switch (textMap.get(teams, membership.teamId)) {
                                        case null {};
                                        case (?team) {
                                            if (team.clubId == clubId) {
                                                hasAccess := true;
                                            };
                                        };
                                    };
                                };
                            };
                        };
                    };
                    case (?teamId) {
                        for (membership in List.toIter(userMemberships)) {
                            if (membership.teamId == teamId) {
                                hasAccess := true;
                            };
                        };
                    };
                };
            };

            if (hasAccess) {
                accessibleThreads := List.push(thread, accessibleThreads);
            };
        };

        List.toArray(accessibleThreads);
    };

    // Child profile functions
    public shared ({ caller }) func createChildProfile(name : Text, dateOfBirth : Text) : async () {
        if (Principal.isAnonymous(caller)) {
            Debug.trap("Anonymous users cannot create child profiles");
        };

        let childProfile : ChildProfile = {
            name = name;
            dateOfBirth = dateOfBirth;
            parent = caller;
        };

        childProfiles := principalMap.put(childProfiles, caller, childProfile);
    };

    public query ({ caller }) func getChildProfiles() : async [ChildProfile] {
        var childList = List.nil<ChildProfile>();
        for ((parent, profile) in principalMap.entries(childProfiles)) {
            if (parent == caller) {
                childList := List.push(profile, childList);
            };
        };
        List.toArray(childList);
    };

    public query ({ caller }) func getParentTeams() : async [Team] {
        var teamList = List.nil<Team>();
        for ((_, membership) in textMap.entries(memberships)) {
            if (membership.userId == caller and membership.role == "parent") {
                switch (textMap.get(teams, membership.teamId)) {
                    case null {};
                    case (?team) {
                        teamList := List.push(team, teamList);
                    };
                };
            };
        };
        List.toArray(teamList);
    };

    public shared ({ caller }) func assignChildToTeam(childName : Text, teamId : Text) : async () {
        // Verify parent has "parent" role in the team
        var isParentInTeam = false;
        for ((_, membership) in textMap.entries(memberships)) {
            if (membership.userId == caller and membership.teamId == teamId and membership.role == "parent") {
                isParentInTeam := true;
            };
        };

        if (not isParentInTeam) {
            Debug.trap("Parent does not have permission to assign child to this team");
        };

        // Find child profile
        var childProfile : ?ChildProfile = null;
        for ((parent, profile) in principalMap.entries(childProfiles)) {
            if (parent == caller and profile.name == childName) {
                childProfile := ?profile;
            };
        };

        switch (childProfile) {
            case null { Debug.trap("Child profile not found") };
            case (?_) {
                // Remove any existing child membership for this child in the team
                let oldMembershipId = childName # "-" # teamId;
                memberships := textMap.delete(memberships, oldMembershipId);

                // Create new membership for child with "player" role
                let newMembershipId = childName # "-" # teamId;
                let newMembership : Membership = {
                    userId = caller; // Using parent's Principal as child identifier
                    teamId = teamId;
                    role = "player";
                };

                memberships := textMap.put(memberships, newMembershipId, newMembership);

                // Update child memberships map
                childMemberships := textMap.put(childMemberships, childName, teamId);
            };
        };
    };

    public query func getChildMemberships() : async [(Text, Text)] {
        Iter.toArray(textMap.entries(childMemberships));
    };

    public query func getAllMemberships() : async [(Text, Membership)] {
        Iter.toArray(textMap.entries(memberships));
    };

    public query func getAllChildProfiles() : async [(Principal, ChildProfile)] {
        Iter.toArray(principalMap.entries(childProfiles));
    };

    public query func getAllTeams() : async [(Text, Team)] {
        Iter.toArray(textMap.entries(teams));
    };

    public query func getAllClubs() : async [(Text, Club)] {
        Iter.toArray(textMap.entries(clubs));
    };

    public query func getAllUsers() : async [(Principal, UserProfile)] {
        Iter.toArray(principalMap.entries(userProfiles));
    };

    public query func getAllMessages() : async [(Text, Message)] {
        Iter.toArray(textMap.entries(messages));
    };

    public query func getAllChatThreads() : async [(Text, ChatThread)] {
        Iter.toArray(textMap.entries(chatThreads));
    };

    public query func getAllFileReferences() : async [Registry.FileReference] {
        Registry.list(registry);
    };

    public query func getAllTime() : async Time.Time {
        Time.now();
    };

    public query func getAllArray() : async [Nat] {
        Array.tabulate<Nat>(10, func(i) { i });
    };

    public query func getAllText() : async Text {
        "Hello World";
    };

    public query func getAllList() : async List.List<Nat> {
        List.push(1, List.nil());
    };

    public query func getAllDebug() : async () {
        Debug.print("Hello World");
    };

    public query func getAllInt() : async Int {
        42;
    };

    public query func getAllNat() : async Nat {
        42;
    };

    public query func getAllPrincipal() : async Principal {
        Principal.fromText("2vxsx-fae");
    };

    // Notification functions
    public shared ({ caller }) func markNotificationAsRead(notificationId : Text) : async () {
        switch (textMap.get(notifications, notificationId)) {
            case null { Debug.trap("Notification not found") };
            case (?notification) {
                if (notification.recipient != caller) {
                    Debug.trap("Cannot mark notification as read for another user");
                };
                let updatedNotification = { notification with isRead = true };
                notifications := textMap.put(notifications, notificationId, updatedNotification);
            };
        };
    };

    public query ({ caller }) func getNotifications() : async [Notification] {
        var userNotifications = List.nil<Notification>();
        for ((_, notification) in textMap.entries(notifications)) {
            if (notification.recipient == caller) {
                userNotifications := List.push(notification, userNotifications);
            };
        };
        List.toArray(userNotifications);
    };

    public query ({ caller }) func getUnreadNotifications() : async [Notification] {
        var unreadNotifications = List.nil<Notification>();
        for ((_, notification) in textMap.entries(notifications)) {
            if (notification.recipient == caller and not notification.isRead) {
                unreadNotifications := List.push(notification, unreadNotifications);
            };
        };
        List.toArray(unreadNotifications);
    };

    public shared ({ caller }) func createNotification(recipient : Principal, notificationType : Text, content : Text, relatedId : ?Text) : async () {
        let notificationId = Principal.toText(caller) # "-" # Int.toText(Time.now());
        let newNotification : Notification = {
            id = notificationId;
            recipient = recipient;
            notificationType = notificationType;
            content = content;
            timestamp = Time.now();
            isRead = false;
            relatedId = relatedId;
            sender = ?caller;
        };
        notifications := textMap.put(notifications, notificationId, newNotification);
    };

    public shared ({ caller }) func createJoinRequestNotification(recipient : Principal, teamId : Text, message : Text) : async () {
        let content = "Join request for team " # teamId # ": " # message;
        await createNotification(recipient, "join_request", content, ?teamId);
    };

    public shared ({ caller }) func createMessageNotification(recipient : Principal, threadId : Text, messagePreview : Text) : async () {
        let content = "New message in thread " # threadId # ": " # messagePreview;
        await createNotification(recipient, "message", content, ?threadId);
    };

    public shared ({ caller }) func createReactionNotification(recipient : Principal, messageId : Text, reaction : Text) : async () {
        let content = "New reaction to your message " # messageId # ": " # reaction;
        await createNotification(recipient, "reaction", content, ?messageId);
    };

    public shared ({ caller }) func approveJoinRequest(notificationId : Text) : async () {
        switch (textMap.get(notifications, notificationId)) {
            case null { Debug.trap("Notification not found") };
            case (?notification) {
                if (notification.recipient != caller or notification.notificationType != "join_request") {
                    Debug.trap("Invalid join request notification");
                };

                // Mark notification as read
                let updatedNotification = { notification with isRead = true };
                notifications := textMap.put(notifications, notificationId, updatedNotification);

                // Create approval notification for requester
                switch (notification.sender) {
                    case null { Debug.trap("No sender for join request notification") };
                    case (?requester) {
                        let approvalContent = "Your join request for " # notification.content # " has been approved";
                        await createNotification(requester, "join_request_approved", approvalContent, notification.relatedId);
                    };
                };
            };
        };
    };

    public shared ({ caller }) func rejectJoinRequest(notificationId : Text) : async () {
        switch (textMap.get(notifications, notificationId)) {
            case null { Debug.trap("Notification not found") };
            case (?notification) {
                if (notification.recipient != caller or notification.notificationType != "join_request") {
                    Debug.trap("Invalid join request notification");
                };

                // Mark notification as read
                let updatedNotification = { notification with isRead = true };
                notifications := textMap.put(notifications, notificationId, updatedNotification);

                // Create rejection notification for requester
                switch (notification.sender) {
                    case null { Debug.trap("No sender for join request notification") };
                    case (?requester) {
                        let rejectionContent = "Your join request for " # notification.content # " has been rejected";
                        await createNotification(requester, "join_request_rejected", rejectionContent, notification.relatedId);
                    };
                };
            };
        };
    };

    public shared ({ caller }) func clearReadNotifications() : async () {
        for ((id, notification) in textMap.entries(notifications)) {
            if (notification.recipient == caller and notification.isRead) {
                notifications := textMap.delete(notifications, id);
            };
        };
    };

    public query ({ caller }) func getNotificationCount() : async Nat {
        var count = 0;
        for ((_, notification) in textMap.entries(notifications)) {
            if (notification.recipient == caller and not notification.isRead) {
                count += 1;
            };
        };
        count;
    };

    public query ({ caller }) func getJoinRequestNotifications() : async [Notification] {
        var joinRequests = List.nil<Notification>();
        for ((_, notification) in textMap.entries(notifications)) {
            if (notification.recipient == caller and notification.notificationType == "join_request" and not notification.isRead) {
                joinRequests := List.push(notification, joinRequests);
            };
        };
        List.toArray(joinRequests);
    };

    public query ({ caller }) func getMessageNotifications() : async [Notification] {
        var messageNotifications = List.nil<Notification>();
        for ((_, notification) in textMap.entries(notifications)) {
            if (notification.recipient == caller and notification.notificationType == "message" and not notification.isRead) {
                messageNotifications := List.push(notification, messageNotifications);
            };
        };
        List.toArray(messageNotifications);
    };

    public query ({ caller }) func getReactionNotifications() : async [Notification] {
        var reactionNotifications = List.nil<Notification>();
        for ((_, notification) in textMap.entries(notifications)) {
            if (notification.recipient == caller and notification.notificationType == "reaction" and not notification.isRead) {
                reactionNotifications := List.push(notification, reactionNotifications);
            };
        };
        List.toArray(reactionNotifications);
    };

    // Event management functions
    public shared ({ caller }) func createEvent(title : Text, description : Text, date : Time.Time, clubId : ?Text, teamId : ?Text, eventType : Text) : async Text {
        if (Principal.isAnonymous(caller)) {
            Debug.trap("Anonymous users cannot create events");
        };

        // Validate club and team if provided
        switch (clubId) {
            case null {};
            case (?cid) {
                switch (textMap.get(clubs, cid)) {
                    case null { Debug.trap("Club not found") };
                    case (?_) {};
                };
            };
        };

        switch (teamId) {
            case null {};
            case (?tid) {
                switch (textMap.get(teams, tid)) {
                    case null { Debug.trap("Team not found") };
                    case (?_) {};
                };
            };
        };

        let eventId = Principal.toText(caller) # "-" # title;

        // Determine invited members based on team or club
        var invitedMembers = List.nil<Principal>();

        switch (teamId) {
            case null {};
            case (?tid) {
                for ((_, membership) in textMap.entries(memberships)) {
                    if (membership.teamId == tid) {
                        invitedMembers := List.push(membership.userId, invitedMembers);
                    };
                };
            };
        };

        switch (clubId) {
            case null {};
            case (?cid) {
                for ((_, team) in textMap.entries(teams)) {
                    if (team.clubId == cid) {
                        for ((_, membership) in textMap.entries(memberships)) {
                            if (membership.teamId == team.id) {
                                invitedMembers := List.push(membership.userId, invitedMembers);
                            };
                        };
                    };
                };
            };
        };

        let newEvent : Event = {
            id = eventId;
            title = title;
            description = description;
            date = date;
            clubId = clubId;
            teamId = teamId;
            createdBy = caller;
            eventType = eventType;
            invitedMembers = List.toArray(invitedMembers);
        };

        events := textMap.put(events, eventId, newEvent);
        eventId;
    };

    public query func getEvent(eventId : Text) : async ?Event {
        textMap.get(events, eventId);
    };

    public query func getAllEvents() : async [Event] {
        Iter.toArray(textMap.vals(events));
    };

    public query func getUpcomingEvents() : async [Event] {
        let now = Time.now();
        var upcomingEvents = List.nil<Event>();
        for ((_, event) in textMap.entries(events)) {
            if (event.date > now) {
                upcomingEvents := List.push(event, upcomingEvents);
            };
        };
        List.toArray(upcomingEvents);
    };

    public shared ({ caller }) func deleteEvent(eventId : Text) : async () {
        switch (textMap.get(events, eventId)) {
            case null { Debug.trap("Event not found") };
            case (?event) {
                if (event.createdBy != caller and not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
                    Debug.trap("Only event creator or admin can delete the event");
                };
                events := textMap.delete(events, eventId);
            };
        };
    };

    // RSVP management functions
    public shared ({ caller }) func submitRSVP(eventId : Text, status : Text) : async () {
        switch (textMap.get(events, eventId)) {
            case null { Debug.trap("Event not found") };
            case (?event) {
                // Check if user is invited
                var isInvited = false;
                for (invited in event.invitedMembers.vals()) {
                    if (invited == caller) {
                        isInvited := true;
                    };
                };

                if (not isInvited) {
                    Debug.trap("User is not invited to this event");
                };

                let rsvpId = Principal.toText(caller) # "-" # eventId;
                let newRSVP : RSVP = {
                    eventId = eventId;
                    userId = caller;
                    status = status;
                    timestamp = Time.now();
                    childName = null;
                };

                rsvps := textMap.put(rsvps, rsvpId, newRSVP);
            };
        };
    };

    public query func getEventRSVPs(eventId : Text) : async [RSVP] {
        var rsvpList = List.nil<RSVP>();
        for ((_, rsvp) in textMap.entries(rsvps)) {
            if (rsvp.eventId == eventId) {
                rsvpList := List.push(rsvp, rsvpList);
            };
        };
        List.toArray(rsvpList);
    };

    public query ({ caller }) func getMyRSVPs() : async [RSVP] {
        var myRSVPs = List.nil<RSVP>();
        for ((_, rsvp) in textMap.entries(rsvps)) {
            if (rsvp.userId == caller) {
                myRSVPs := List.push(rsvp, myRSVPs);
            };
        };
        List.toArray(myRSVPs);
    };

    public shared ({ caller }) func submitChildRSVP(eventId : Text, childName : Text, status : Text) : async () {
        // Verify parent has child profile
        var hasChild = false;
        for ((parent, profile) in principalMap.entries(childProfiles)) {
            if (parent == caller and profile.name == childName) {
                hasChild := true;
            };
        };

        if (not hasChild) {
            Debug.trap("Child profile not found for parent");
        };

        switch (textMap.get(events, eventId)) {
            case null { Debug.trap("Event not found") };
            case (?event) {
                // Check if child is invited (using parent's Principal as identifier)
                var isChildInvited = false;
                for (invited in event.invitedMembers.vals()) {
                    if (invited == caller) {
                        isChildInvited := true;
                    };
                };

                if (not isChildInvited) {
                    Debug.trap("Child is not invited to this event");
                };

                let rsvpId = childName # "-" # eventId;
                let newRSVP : RSVP = {
                    eventId = eventId;
                    userId = caller; // Using parent's Principal as child identifier
                    status = status;
                    timestamp = Time.now();
                    childName = ?childName;
                };

                rsvps := textMap.put(rsvps, rsvpId, newRSVP);
            };
        };
    };

    public query func getAllRSVPs() : async [(Text, RSVP)] {
        Iter.toArray(textMap.entries(rsvps));
    };

    // New function to update an event
    public shared ({ caller }) func updateEvent(eventId : Text, title : Text, description : Text, date : Time.Time, clubId : ?Text, teamId : ?Text, eventType : Text, invitedMembers : [Principal]) : async () {
        switch (textMap.get(events, eventId)) {
            case null { Debug.trap("Event not found") };
            case (?event) {
                if (event.createdBy != caller and not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
                    Debug.trap("Only event creator or admin can update the event");
                };

                let updatedEvent : Event = {
                    id = eventId;
                    title = title;
                    description = description;
                    date = date;
                    clubId = clubId;
                    teamId = teamId;
                    createdBy = event.createdBy;
                    eventType = eventType;
                    invitedMembers = invitedMembers;
                };

                events := textMap.put(events, eventId, updatedEvent);
            };
        };
    };
};
