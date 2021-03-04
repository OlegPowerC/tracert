package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	validateip "github.com/OlegPowerC/validate_ipaddresses"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
	"os"
	"sort"
	"time"
)

type HopStats struct {
	HopAdress       net.Addr
	HopFQDN         string
	HopSend         int
	HopRecived      int
	HopLoss         int
	HopLossPercents int
	RTTSumm         int64
	Iteration       int
	SilentHop       bool
}

type First8ByteICMP struct {
	ICMPType int
	ICMPCode int
	ICMPId   uint16
	ICMPSec  uint16
}

func FirstICMP8Unmarshal(data []byte, raw bool) (ICMPshortInfo First8ByteICMP, UnmarshalError error) {
	var Retval First8ByteICMP
	if len(data) < 8 {
		return Retval, fmt.Errorf("Too short data")
	}

	if raw {
		Retval.ICMPType = int(data[0])
		Retval.ICMPCode = int(data[1])
		Retval.ICMPId = binary.BigEndian.Uint16((data[4:6]))
		if len(data) > 8 {
			Retval.ICMPSec = binary.BigEndian.Uint16((data[6:8]))
		} else {
			Retval.ICMPSec = binary.BigEndian.Uint16((data[6:]))
		}
	} else {
		Retval.ICMPId = binary.BigEndian.Uint16((data[0:2]))
		Retval.ICMPSec = binary.BigEndian.Uint16((data[2:4]))
	}

	return Retval, nil
}

func main() {
	host := flag.String("h", "", "IP адрес хоста")
	source := flag.String("s", "0.0.0.0", "IP адрес источника")
	maximum_hopes := flag.Int("t", 50, "Максимальное значение TTL")
	send_count := flag.Int("c", 10, "Количество посылаемых пакетов")
	time_wor_wait_answer := flag.Int64("tw", 1, "Ожидание ответа в секундах")
	debugmode := flag.Bool("d", false, "Режим отладки")
	flag.Parse()

	fmt.Println(`===========================================================
Запускать из превилегированой команднной строки.
Наличие потерь на промежуточных узлах информирует лишь о том, что они декриментировали TTL до нуля
Но не сообщили о том что TTL истек
Задерка ответа - время между отправкой данных с малым TTL и ICMP ответом маршрутизатора
На большинстве современных маршрутизаторов, для снижения нагрузки на процессор, ICMP ответы не являются приоритетными
таким образом промежуточный маршрутизатор может отвечать с большой задержкой или потерями или не отвечать вовсе
но конечый узел может быть при этом доступен без потерь и отвечать с меьшей задержкой
В случае же наличия потерь на конечном узле, возможны проблемы с доступом к сети
===========================================================`)

	if validateip.CheckSingleIp(*host) != nil {
		//Это не IP адрес, пробуем сделать Lookup
		iips, iipserror := net.LookupIP(*host)
		if iipserror != nil {
			fmt.Println(iipserror)
			os.Exit(1)
		} else {
			if len(iips) > 0 {
				*host = iips[0].String()
			}
		}
	}

	fmt.Println("Проверка маршрута и сборка статистики к узлу:", *host)

	hops := make(map[int]*HopStats)
	cn, er := icmp.ListenPacket("ip4:icmp", *source)
	if er != nil {
		fmt.Println(er)
	}

	defer cn.Close()

	ICMPidToSend := os.Getpid()
	ICMPsecToSend := 0

	var SentTime time.Time
	var RTT int64

	printcounter := 0
	validreplay := false
	for try_counter := 0; try_counter <= *send_count; try_counter++ {
		for a := 1; a <= *maximum_hopes; a++ {
			printcounter++
			if try_counter > 0 {
				fmt.Print(".")
				if printcounter%20 == 0 {
					fmt.Println("")
				}
				if _, ok := hops[a]; ok {
					HopStat := hops[a]
					if HopStat.SilentHop {
						continue
					}
					HopStat.HopSend++
					hops[a] = HopStat
				}
			} else {
				printcounter = 0
			}

			ICMPsecToSend++
			im := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: ICMPidToSend, Data: []byte("PowerC echo for PRTG"), Seq: ICMPsecToSend}}

			imm, errm := im.Marshal(nil)
			if errm != nil {
				fmt.Println(errm)
			}

			cn.IPv4PacketConn().SetTTL(a)
			tm1 := time.Duration(*time_wor_wait_answer)
			cn.SetReadDeadline(time.Now().Add(tm1 * time.Second))
			SentTime = time.Now()
			_, wer := cn.WriteTo(imm, &net.IPAddr{IP: net.ParseIP(*host)})
			validreplay = false

			if wer != nil {
				fmt.Println(wer)
			}

			var rp *icmp.Message
			var per error
			var peer net.Addr
			n := 0
			var err error

			for readpacketcount := 0; readpacketcount < 1000; readpacketcount++ {
				rb := make([]byte, 1600)
				n, peer, err = cn.ReadFrom(rb)
				RTime := time.Now()
				RTT = RTime.Sub(SentTime).Microseconds()
				if *debugmode {
					fmt.Println(string(rb))
				}
				if err != nil {
					neterr := err.(net.Error)
					if *debugmode {
						fmt.Println(neterr)
						fmt.Println(hex.EncodeToString(rb))
					}
					if neterr.Timeout() {
						if try_counter == 0 {
							fmt.Println("Нет ответа")
							hops[a] = &HopStats{HopAdress: peer, HopFQDN: "", HopSend: 0, HopRecived: 0, HopLoss: 0, HopLossPercents: 0, SilentHop: true}
						}
					} else {
						fmt.Println(err)
					}
					break
				}

				rp, per = icmp.ParseMessage(1, rb[:n])
				if per != nil {
					fmt.Println("Ошибка разбора ICMP пакета", per, peer)
					continue
				}

				bmsfull, _ := rp.Body.Marshal(1)
				if rp.Type == ipv4.ICMPTypeTimeExceeded {
					bms := bmsfull[4:]
					if len(bms) > 0 {
						if bms[0]&0xF0 == 0x40 {
							ipheaderlength := int(bms[0] & 0x0F * 4)
							fulllen := len(bms)
							lendata := fulllen - ipheaderlength
							if ipheaderlength < fulllen && *debugmode {
								ipheader, ipheaderparseerr := ipv4.ParseHeader(bms[:ipheaderlength])
								fmt.Println("ipheader", ipheader, ipheaderparseerr)
							}
							if lendata > 0 {
								ICMPData, ICMPerr := FirstICMP8Unmarshal(bms[ipheaderlength:], true)
								if ICMPerr != nil {
									fmt.Println(ICMPerr)
									continue
								}
								CpId := uint16(ICMPidToSend)
								CpSec := uint16(ICMPsecToSend)
								if ICMPData.ICMPId == CpId && ICMPData.ICMPSec == CpSec {
									//Наш ответ!
									validreplay = true
									break
								} else {
									continue
								}
							}
						}
					}
				}
				if rp.Type == ipv4.ICMPTypeEchoReply {
					if len(bmsfull) > 12 {
						ICMPData, ICMPerr := FirstICMP8Unmarshal(bmsfull, false)
						if ICMPerr != nil {
							continue
						}
						CpId := uint16(ICMPidToSend)
						CpSec := uint16(ICMPsecToSend)
						if ICMPData.ICMPId == CpId && ICMPData.ICMPSec == CpSec {
							//Наш ответ!
							validreplay = true
							break
						} else {
							continue
						}
					}
				}
			}

			if !validreplay {
				continue
			}

			if try_counter == 0 {
				FQDN := "ptr запись не найдена"
				ptrs, _ := net.LookupAddr(peer.String())
				for ptrindex, ptr := range ptrs {
					if ptrindex == 0 {
						FQDN = ptr
					} else {
						FQDN += ","
						FQDN += ptr
					}
				}
				SFprint := fmt.Sprintf("Получен: %s от: %s (%s)", rp.Type, peer, FQDN)
				fmt.Println(SFprint)

				hops[a] = &HopStats{HopAdress: peer, HopFQDN: FQDN, HopSend: 0, HopRecived: 0, HopLoss: 0, HopLossPercents: 0, RTTSumm: RTT, Iteration: 1, SilentHop: false}
			} else {
				if _, ok := hops[a]; ok {
					HopStat := hops[a]
					HopStat.HopRecived++
					HopStat.RTTSumm += RTT
					HopStat.Iteration++
					hops[a] = HopStat
				}
			}

			if rp.Type == ipv4.ICMPTypeEchoReply {
				if try_counter == 0 {
					fmt.Println("Трассировка завершена")
					fmt.Println("Сборка статистики (только по ответившим узлам)")
				}
				break
			}
		}
	}

	fmt.Println("\r\n===========================================================")
	hopindexes := make([]int, 0)
	for hopindex, _ := range hops {
		hopindexes = append(hopindexes, hopindex)
	}
	sort.Ints(hopindexes)
	for _, hopinmap := range hopindexes {
		currenthop := hops[hopinmap]
		if currenthop.SilentHop {
			continue
		}
		percentloss := 100 - (float64(currenthop.HopRecived) / float64(currenthop.HopSend) * 100)
		AverageRTT := float64(currenthop.RTTSumm) / float64(currenthop.Iteration)
		AverageRTT = AverageRTT / 1000
		pstr := fmt.Sprintf("Задержка ответа: %.2fms Узел: %s (%s) Отправлено: %d Получео: %d Потеряно: %.0f%%", AverageRTT, currenthop.HopAdress.String(), currenthop.HopFQDN, currenthop.HopSend, currenthop.HopRecived, percentloss)
		fmt.Println(pstr)
	}
}
