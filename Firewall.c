#include <gtk/gtk.h> //gtk for building the interface
#include <pthread.h> //for creating threads
#include <unistd.h> //for standard things(functions like strncpy,printf
#include<netinet/in.h> //for internet socket definition descriptions(mostly incoming connections)
#include<errno.h> //for error handling functions
#include<netdb.h> 
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For all (ETH_P_ALL) ethernet headers  packet
#include<net/ethernet.h>  //For ether_header 
#include<sys/socket.h> //for socket creation function
#include<arpa/inet.h> // arp internet definitions and functions
#include<sys/ioctl.h> //ioctl- manipulates the underlying device parameters of  special files.
#include<sys/time.h> //for time functions eg . sleep(),usleep()
#include<sys/types.h> // defining type definition
#include <linux/netdevice.h> // hardware devices
 
//function prototypes
void settings_button(GtkWidget *widget, gpointer data); // for initialising the settings interface
void statistics_button(GtkWidget *widget, gpointer data);// for  for showing statistics
void* monitordisplay(void* labelmonijr); //for starting the monitor display
void* caller(void* unsued);// for calling the threads
int packetanalyser(void);//main packet analyser
void ProcessPacket(unsigned char* , int);//packet processor
void print_ip_header(unsigned char* , int);//function to print the ip header stat for packet to statistics log file
void print_tcp_packet(unsigned char * , int );//function to print the tcp header stat for packet to statistics log file
void print_udp_packet(unsigned char * , int );//function to print the udp header stat for packet to statistics log file
void print_icmp_packet(unsigned char* , int );//function to print the icmp header stat for packet to statistics log file
void PrintData (unsigned char* , int);//prints out the payload data in hex and ascii
void monitor_button(GtkWidget *widget, gpointer data); //function to start the monitor window

FILE *logfile;//pointer to the statistics log file
struct sockaddr_in source,dest;//structure to keep track of socket address source and destination for packets
 
#define MAXINTERFACES 20
int dns=0, tcp=0,udp=0,icmp=0,others=0,igmp=0,packetsdroped=0,total=0,i,j;
pthread_t thread_id;
pthread_t thread_id2;
pthread_t thread_id3;
int encrypt=0,flood=0,large=0,traffic=0;

unsigned int toggledthread=0;
unsigned int payloadsize=0;
unsigned int dnspacketsize=500;
unsigned int icmppacketsize=1024;





//Toggle start engine
void Startengine(void){
                //this if statementt checks the status of the user selected options from the interface to determine which running configurations the router shall use: the value 0 means off and the value 1 means on
if(encrypt==1 && flood==1 && large==1 && traffic==1){
    switch (toggledthread) 
    {
        case 0:  
           toggledthread=1;
           pthread_create(&thread_id2, NULL, &caller, NULL);
           break;
         
        case 1:  
           pthread_cancel(thread_id2); 
           toggledthread=0;                                        
           printf("\nEngine Succeffully Stopped!\n\n");
           break;
         
    }

                       }

if(encrypt!=1 || flood!=1 || large!=1 || traffic!=1){

// code for windows which gives info on whether the firewall rules have all been ticket
 GtkWidget *windowD = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_position(GTK_WINDOW(windowD), GTK_WIN_POS_CENTER);
  gtk_window_set_default_size(GTK_WINDOW(windowD), 500, 500);
  gtk_window_set_title(GTK_WINDOW(windowD), "Message dialogs");
  GtkWidget *dialog;
  dialog = gtk_message_dialog_new(GTK_WINDOW(windowD),
            GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_WARNING,
            GTK_BUTTONS_OK,
            "Unallowed operation.Please ensure that all Firewall rules are ticked!!");
  gtk_window_set_title(GTK_WINDOW(dialog), "Warning");
  gtk_dialog_run(GTK_DIALOG(dialog));
  gtk_widget_destroy(dialog);

}








}


//close the settings window from the interface
void Close_settings(GtkWidget *widget, gpointer windata){
 
    gtk_widget_hide(windata);//destroys the window(closes it) it receives the point to the window as the parameter

}


//getter to acquire the inteface details: mac address,ip addres and subnet mask(net mask)
char* getter(char *c)
{
	int fd;
	struct ifreq ifr;// structure to keep interface details
	char *iface =c;
        char s1[100];
        char s2[100];
        char *s3;
        char s4[100];
	unsigned char *mac;
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	//Type of address to retrieve - IPv4 IP address
	ifr.ifr_addr.sa_family = AF_INET;

	//Copy the interface name in the ifreq structure
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	
         //get mac address
        ioctl(fd, SIOCGIFHWADDR, &ifr);
        
        mac=(unsigned char *)ifr.ifr_hwaddr.sa_data;//casting the hardware address to the unsigned charackter string 

	//display mac address
       sprintf(s1,"Mac Address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	

        //get the ip address
	ioctl(fd, SIOCGIFADDR, &ifr);
	//display ip
	sprintf(s2,"IP  address: %s\n" ,inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );/* this function gets the ip address of the inteface. depending on the status of the system(whether it uses little endian or big endian. it changes it to network byte order.*/


	s3=strcat ( s1,s2 );

	//get the netmask ip
	ioctl(fd, SIOCGIFNETMASK, &ifr);
	
	//display netmask
	sprintf(s4,"Netmask    : %s\n" ,inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );
       strcat ( s3,s4 );
       close(fd);
	
	return s3;
}


//combo box for selecting subnet card
void combo_selectedsubnet(GtkWidget *widget, gpointer window)
{

  gchar *text =  gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget));//gets active text from the combo box
  gchar *rettext =getter(text);
  interfacesubnet=text;
 
  gtk_label_set_text(GTK_LABEL(window), rettext);
  g_free(text);
 
}

//combo box for selecting internet/gateway card
void combo_selectedinternet(GtkWidget *widget, gpointer window)
{

  gchar *text =  gtk_combo_box_get_active_text(GTK_COMBO_BOX(widget));
  gchar *rettext =getter(text);
  interfaceinternet=text;

  gtk_label_set_text(GTK_LABEL(window), rettext);
  g_free(text);
 
}


void toggle_titleicmp(GtkWidget *widget, gpointer window)
{
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))) 
      encrypt=1;
  if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))) 
      encrypt=0;	
}

void toggle_titledns(GtkWidget *widget, gpointer window)
{
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))) 
      flood=1;
  if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))) 
      flood=0;	
}
void toggle_titleudp(GtkWidget *widget, gpointer window)
{
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))) 
      large=1;
  if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))) 
      large=0;	
}
void toggle_titletcp(GtkWidget *widget, gpointer window)
{
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))) 
      traffic=1;
  if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget))) 
      traffic=0;	
}

//socket error function from settings window
void diep(char *s)
{
    perror(s);//error inbuilt function
    exit(1);
}

// the settings window
void settings_button(GtkWidget *widget, gpointer data)
{
  GtkWidget *window2;
  GtkWidget *table;
  GtkWidget *vbox2;
  GtkWidget *vbox3;

  GtkWidget *labelsubnet;
  GtkWidget *labelconfig;
  GtkWidget *button1;
  GtkWidget *frame1;
  GtkWidget *frame2;
  GtkWidget *frame3;
  GtkWidget *frame4;
  GtkWidget *checkicmp;
  GtkWidget *checkdns;
  GtkWidget *checkudp;
  GtkWidget *checktcp;
  GtkWidget *vbox;
  GtkWidget *toolbar;
  GtkWidget *labelinternet;
  GtkToolItem *save;
  GtkToolItem *sep;
  GtkToolItem *exit;
  GtkWidget *fixedsubnet;
  GtkWidget *fixedinternet;
  GtkWidget *combointernet;
  GtkWidget *combosubnet;
  char bufsub[100];
    int sock;
    struct ifconf ifconf;
    struct ifreq ifreq[MAXINTERFACES];
    int interfaces;
    int i;
 
    // Create a socket or return an error.
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        diep("socket");
 
    // Point ifconf's ifc_buf to our array of interface ifreqs.
    ifconf.ifc_buf = (char *) ifreq;
    
    // Set ifconf's ifc_len to the length of our array of interface ifreqs.
    ifconf.ifc_len = sizeof ifreq;
 
    //  Populate ifconf.ifc_buf (ifreq) with a list of interface names and addresses.
    if (ioctl(sock, SIOCGIFCONF, &ifconf) == -1)
        diep("ioctl");
 
    // Divide the length of the interface list by the size of each entry.
    // This gives us the number of interfaces on the system.
    interfaces = ifconf.ifc_len / sizeof(ifreq[0]);
 

  //window setup
  window2 = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_position(GTK_WINDOW(window2), GTK_WIN_POS_CENTER);
  gtk_window_set_default_size(GTK_WINDOW(window2), 500, 500);
  gtk_window_set_title(GTK_WINDOW(window2), "Settings");
  gtk_container_set_border_width(GTK_CONTAINER(window2), 10);

  
   vbox2 = gtk_vbox_new(FALSE, 0);
   gtk_container_add(GTK_CONTAINER(window2), vbox2);

  //vertical box setup for frame3 adding checkboxes to the vetical box
  gtk_container_set_border_width(GTK_CONTAINER(vbox2), 0);
  
  vbox3 = gtk_vbox_new(FALSE, 0);



  toolbar = gtk_toolbar_new();
  gtk_toolbar_set_style(GTK_TOOLBAR(toolbar), GTK_TOOLBAR_ICONS);

  gtk_container_set_border_width(GTK_CONTAINER(toolbar), 2);


  save = gtk_tool_button_new_from_stock(GTK_STOCK_SAVE);
  gtk_toolbar_insert(GTK_TOOLBAR(toolbar), save, -1);

  sep = gtk_separator_tool_item_new();
  gtk_toolbar_insert(GTK_TOOLBAR(toolbar), sep, -1); 

  exit = gtk_tool_button_new_from_stock(GTK_STOCK_QUIT);
  gtk_toolbar_insert(GTK_TOOLBAR(toolbar), exit, -1);

  gtk_box_pack_start(GTK_BOX(vbox3), toolbar, FALSE, FALSE, 3);
  gtk_box_pack_start(GTK_BOX(vbox2), vbox3, FALSE, FALSE, 0);

  //table containter setup
  table = gtk_table_new(2, 2, TRUE);
  gtk_table_set_row_spacings(GTK_TABLE(table), 10);
  gtk_table_set_col_spacings(GTK_TABLE(table), 10);
  gtk_box_pack_start(GTK_BOX(vbox2), table, TRUE, TRUE, 0);
  //frames initialisation
  frame1 = gtk_frame_new("Sub-Net Addres(Card):");
  gtk_frame_set_shadow_type(GTK_FRAME(frame1), GTK_SHADOW_IN);
  frame2 = gtk_frame_new("Gateway Address(Card):");
  gtk_frame_set_shadow_type(GTK_FRAME(frame2), GTK_SHADOW_OUT);
  frame3 = gtk_frame_new("Traffic monitoring");
  gtk_frame_set_shadow_type(GTK_FRAME(frame3), GTK_SHADOW_ETCHED_IN);
  frame4 = gtk_frame_new("Running configuration:");
  gtk_frame_set_shadow_type(GTK_FRAME(frame4), GTK_SHADOW_ETCHED_OUT);
   

  //subnet card details
  fixedsubnet = gtk_fixed_new();

  combosubnet = gtk_combo_box_new_text();
 // Loop through the array of interfaces, printing each one's name and IP.
    for (i = 0; i < interfaces; i++) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *address = (struct sockaddr_in *) &ifreq[i].ifr_addr;
 
        // Convert the binary IP address into a readable string.
        if (!inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip)))
            diep("inet_ntop");
 
        sprintf(bufsub,"%s", ifreq[i].ifr_name);
        gtk_combo_box_append_text(GTK_COMBO_BOX(combosubnet), bufsub);
    }



  gtk_fixed_put(GTK_FIXED(fixedsubnet), combosubnet, 50, 50);
  gtk_container_add(GTK_CONTAINER(frame1), fixedsubnet);

  labelsubnet = gtk_label_new("select an interface");
  gtk_fixed_put(GTK_FIXED(fixedsubnet), labelsubnet, 50, 110);
 


  //internet card details
  fixedinternet = gtk_fixed_new();

  combointernet = gtk_combo_box_new_text();
   
    
    // Loop through the array of interfaces, printing each one's name and IP.
    for (i = 0; i < interfaces; i++) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *address = (struct sockaddr_in *) &ifreq[i].ifr_addr;
 
        // Convert the binary IP address into a readable string.
        if (!inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip)))
            diep("inet_ntop");
 
        sprintf(bufsub,"%s", ifreq[i].ifr_name);
        gtk_combo_box_append_text(GTK_COMBO_BOX(combointernet), bufsub);
    }
 
    close(sock);













  gtk_fixed_put(GTK_FIXED(fixedinternet), combointernet, 50, 50);
  gtk_container_add(GTK_CONTAINER(frame2), fixedinternet);

  labelinternet = gtk_label_new("select an interface");
  gtk_fixed_put(GTK_FIXED(fixedinternet), labelinternet, 50, 110);

  //frame3 set up for check boxes
  vbox = gtk_vbox_new(TRUE, 1);
  gtk_container_add(GTK_CONTAINER(frame3), vbox);
  checkicmp=gtk_check_button_new_with_label("ICMP/DNS-Encrypted Traffic");
  checkdns= gtk_check_button_new_with_label("ICMP/DNS-Flooding Traffic");
  checkudp= gtk_check_button_new_with_label("ICMP/DNS-Packets Too Large");
  checktcp= gtk_check_button_new_with_label("ICMP/DNS-Internet Traffic");


 
  //frames setup add them to the table container
  gtk_table_attach_defaults(GTK_TABLE(table), frame1, 0, 1, 0, 1);
  gtk_table_attach_defaults(GTK_TABLE(table), frame2, 0, 1, 1, 2);
  gtk_table_attach_defaults(GTK_TABLE(table), frame3, 1, 2, 0, 1);
  gtk_table_attach_defaults(GTK_TABLE(table), frame4, 1, 2, 1, 2);



  //vertical box setup for frame3 adding checkboxes to the vetical box
  gtk_container_set_border_width(GTK_CONTAINER(vbox), 40);
  gtk_box_pack_start(GTK_BOX(vbox), checkicmp, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), checkdns, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), checkudp, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), checktcp, FALSE, TRUE, 0);
  
   labelconfig = gtk_label_new("Configuration:\n\nDNS:ON\nICMP:ON\nTCP:ON\nUDP:ON\nIGMP:ON\n OTHER:ON\n\nRules codes:\n1-DNS/ICMP ENCRYPTED DROP\n2-DNS/ICMP PACKET TOO LARGE DROP\n3-DNS/ICMP PACKET TRAFFIC TOO HIGH OR TOO FLOODED OR FREQUENT DROP/BLOCK\n4-ALL COMING FROM OUTSIDE NETWORK DROP\n");

  gtk_label_set_justify(GTK_LABEL(labelconfig), GTK_JUSTIFY_LEFT);
  gtk_container_add(GTK_CONTAINER(frame4), labelconfig);


  //signals and events
  g_signal_connect(checkicmp, "clicked",G_CALLBACK(toggle_titleicmp),NULL);
  g_signal_connect(checkdns, "clicked",G_CALLBACK(toggle_titledns),NULL);
  g_signal_connect(checkudp, "clicked",G_CALLBACK(toggle_titleudp),NULL);
  g_signal_connect(checktcp, "clicked",G_CALLBACK(toggle_titletcp),NULL);



  g_signal_connect_swapped(G_OBJECT(window2), "destroy",G_CALLBACK(Close_settings), G_OBJECT(window2));//signal connectors
  g_signal_connect(G_OBJECT(combosubnet), "changed",G_CALLBACK(combo_selectedsubnet), (gpointer) labelsubnet);
  g_signal_connect(G_OBJECT(combointernet), "changed",G_CALLBACK(combo_selectedinternet), (gpointer) labelinternet);
  g_signal_connect(G_OBJECT(exit), "clicked", G_CALLBACK(Startengine), NULL);
  gtk_widget_show_all(window2);
}


//opens the statistics in file in the text editor. eg. Gedit
void* stats(void* unused){

system("xdg-open log.txt");

}


//The statistics window
void statistics_button(GtkWidget *widget, gpointer data)
{
  
  pthread_create(&thread_id3, NULL, &stats, NULL);
}




void* monitordisplay(void* labelmonijr)
{

GtkWidget *wet=(GtkWidget*)labelmonijr;
char strd[400];
   for(;;){
   sleep(1);
   sprintf(strd,"TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d   droped:%d\r",tcp,udp,icmp,igmp,others ,total,packetsdroped);
   gtk_label_set_text(GTK_LABEL(wet), strd);//sets the label on the traffic monitor interface

          }
}

void* caller(void* unsued){
packetanalyser();
}

int packetanalyser(void){
    int saddr_size , data_size;
    struct sockaddr saddr;
         
    unsigned char *buffer = (unsigned char *) malloc(65536); //a large enough 
     
    logfile=fopen("log.txt","w");//opens the log.txt file ,if it does not exist it creats a new one..w means open the file in writable mode
    if(logfile==NULL)
    {
        printf("Unable to create log.txt file.");
    }
     
    printf("Starting...\n");
    int sock_raw = socket(AF_PACKET, SOCK_RAW , htons(ETH_P_ALL)) ;//creating of the raw socket

    setsockopt(sock_raw ,SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );//setting socket options and binding the socket to the card
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return ;
    }

    printf("Firewall Started successfully\n");
    printf("Real Time Traffic Monitor Started:\n");
    while(1)
    {
        saddr_size = sizeof saddr;

        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
       
        //Now process the packet
        ProcessPacket(buffer , data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}


void ProcessPacket(unsigned char* buffer, int size) // to  Process the packet pass the address to the buffer where the packet is stored.
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));//casting buffer + size of ethernet header address to ip header address

    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet( buffer , size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
printf("TCP : %d  UDP : %d   ICMP : %d   IGMP : %d   Others : %d  Total : %d droped:%d\r",tcp,udp,icmp,igmp,others ,total,packetsdroped);

}
 

void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;//casting buffer address of character to ethernet structure
     
    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}
 
void print_ip_header(unsigned char* Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );//casting
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));//sets asside memory space of size of source addres struct from the address &source.
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
   payloadsize = ntohs(iph->tot_len)-((unsigned int)(iph->ihl))*4;
     
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    fprintf(logfile , "   |-payload size  : %d\n",payloadsize);

}
 
void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    fprintf(logfile , "\n\n***********************TCP Packet*************************\n"); 
         
    print_ip_header(Buffer,Size);
         
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");
         
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(logfile , "Data Payload\n");   
    PrintData(Buffer + header_size , Size - header_size );
                         
    fprintf(logfile , "\n###########################################################");
}
 
void print_udp_packet(unsigned char *Buffer , int Size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(Buffer,Size);          
    if(ntohs(udph->dest)==53 && payloadsize>dnspacketsize){
     packetsdroped++;
     fprintf(logfile , "DNS Packet Dropped:\ncomment:Packet larger preset %d bytes\n\n",dnspacketsize);  
}
    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    fprintf(logfile , "Data Payload\n");   
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);
     
    fprintf(logfile , "\n###########################################################");
}
 
void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");
     
    print_ip_header(Buffer , Size);
             
    fprintf(logfile , "\n");
         
    fprintf(logfile , "ICMP Header\n");
    fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }
     
    fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile , "\n");
    if(payloadsize>icmppacketsize){
     packetsdroped++;
     fprintf(logfile , "ICMP Packet Dropped:\ncomment:Packet larger preset %d bytes\n\n",icmppacketsize);   
     }
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
         
    fprintf(logfile , "Data Payload\n");   
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );
     
    fprintf(logfile , "\n###########################################################");
}
 
void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        }
         
        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
              fprintf(logfile , "   "); //extra spaces
            }
             
            fprintf(logfile , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }
             
            fprintf(logfile ,  "\n" );
        }
    }
}








//close traffic monitor window
void Close(GtkWidget *widget, gpointer windata){
  int es = pthread_cancel(thread_id);
           if (es != 0)
             printf("thread not successfully cancelled");
    gtk_widget_hide(windata);

}







//The Traffic monitoring window
void monitor_button(GtkWidget *widget, gpointer data)
{
  GtkWidget *window4;
  GtkWidget *labelmoni;


  window4 = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_position(GTK_WINDOW(window4), GTK_WIN_POS_CENTER);
  gtk_window_set_title(GTK_WINDOW(window4), "Traffic Monitor(per second)");

  char strmoni[400];
sprintf(strmoni,"TCP : %d  UDP : %d   ICMP : %d   IGMP : %d   Others : %d  Total : %d droped:%d\r",tcp,udp,icmp,igmp,others ,total,packetsdroped);
  labelmoni = gtk_label_new(NULL);
  gtk_label_set_markup(GTK_LABEL(labelmoni), strmoni);

  gtk_label_set_justify(GTK_LABEL(labelmoni), GTK_JUSTIFY_CENTER);
  gtk_container_add(GTK_CONTAINER(window4), labelmoni);
  gtk_widget_show(labelmoni);

  gtk_window_set_default_size(GTK_WINDOW(window4), 500, 100);

  g_signal_connect(window4, "destroy",G_CALLBACK (Close),window4);

  gtk_widget_show(window4);

  
  pthread_create(&thread_id, NULL, &monitordisplay, labelmoni);
}








// Main function where the execution of the firewall program begins
int main( int argc, char *argv[])
{

  GtkWidget *window;
  GtkWidget *vboxini;

  GtkWidget *Settings;
  GtkWidget *Statistics;
  GtkWidget *Monitor;
  GtkWidget *statusbar;

  gtk_init(&argc, &argv);

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
  gtk_window_set_default_size(GTK_WINDOW(window), 500, 500);
  gtk_window_set_title(GTK_WINDOW(window), "The Packet Filter Firewall");
  gtk_container_set_border_width(GTK_CONTAINER(window), 20);

  vboxini = gtk_vbox_new(TRUE, 3);
  gtk_container_add(GTK_CONTAINER(window), vboxini);

  Settings = gtk_button_new_with_label("Settings");
  Statistics = gtk_button_new_with_label("Statistics");
  Monitor = gtk_button_new_with_label("Traffic Monitor");

  statusbar = gtk_statusbar_new();

  gtk_box_pack_start(GTK_BOX(vboxini), Settings, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(vboxini), Statistics, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(vboxini), Monitor, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(vboxini), statusbar, FALSE, TRUE, 0);

//g_signal is used in gtk to connect a widget to an event or signal
  g_signal_connect(G_OBJECT(Settings), "clicked",G_CALLBACK(settings_button), NULL);
  g_signal_connect(G_OBJECT(Statistics), "clicked",G_CALLBACK(statistics_button), NULL);
  g_signal_connect(G_OBJECT(Monitor), "clicked",G_CALLBACK(monitor_button), NULL);

  g_signal_connect_swapped(G_OBJECT(window), "destroy", G_CALLBACK(gtk_main_quit), G_OBJECT(window));

  gtk_widget_show_all(window);

  gtk_main();

  return 0;
}
