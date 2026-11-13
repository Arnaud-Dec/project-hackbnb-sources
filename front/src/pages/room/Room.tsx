import { useEffect, useState, type FormEvent } from "react"
import { apiRoomDetails } from "../../api/rooms.api"
import type { Room } from "../../types/room"
import { useParams } from "react-router-dom"
import { apiBookingNew } from "../../api/bookings.api"

/**
 * The page of a room details
 */
export const RoomPage = () => {
    const { roomId } = useParams()
    const [room, setRoom] = useState<Room>()
    const [arrivalDate, setArrivalDate] = useState<string>('')
    const [departureDate, setDepartureDate] = useState<string>('')
    const [guestsCount, setGuestsCount] = useState<number>(1)

    const reloadRoomDetails = async () => {
        const response = await apiRoomDetails(`${roomId}`)
        setRoom(response.data)
    }

    useEffect(() => {
        reloadRoomDetails()
    }, [])

    const onSubmit = async (event: FormEvent) => {
        event.preventDefault()

        try {
            const res = await apiBookingNew(roomId!, arrivalDate, departureDate, guestsCount)
            alert('Pour tester le paiement, utilisez :\n- numéro de CB : 4242 4242 4242 4242\n- expire : 12/25\n- CVC : 123')
            window.open(res.data.checkout_url, "_blank")
        } catch (error) {
            alert((error as any).response?.data?.error || 'Une erreur est survenue, la clé API Stripe est-elle correcte ?')
        }

        return false
    }

    return <>
        {room && <div className="max-w-7xl m-auto px-5 py-8">
            <div className="flex gap-10">
                <div>
                    <img src={`/api/uploads/?name=${encodeURIComponent(room.picture)}`} className="h-120 rounded-3xl" />
                </div>
                <div className="mt-5">
                    <h1 className="text-xl">{room.title}</h1>
                    <h2 className="mt-1 text-md text-gray-300">{room.city}</h2>

                    <h2 className="mt-4 text-md text-gray-300">Hôte : {room.host?.name}</h2>

                    {/* D7 */}
                    <div className="mt-8 whitespace-pre-line">{room.description}</div>

                    <div className="m-auto mt-10 rounded-3xl p-8 border-1 border-gray-300">
                        <h2 className="text-xl">
                            <strong className="text-gray-100">{room.price} &euro;</strong> par nuit
                        </h2>
                        <form onSubmit={onSubmit}>
                            <div className="flex gap-8 mr-3">
                                <div className="mt-6">
                                    <div className="ml-2">
                                        Arrivée
                                    </div>
                                    <input
                                        type="date"
                                        className="rounded-3xl border-1 border-gray-300 w-full h-10 px-4 mt-2"
                                        value={arrivalDate}
                                        onChange={(e) => setArrivalDate(e.target.value)}
                                        required />
                                </div>
                                <div className="mt-6">
                                    <div className="ml-2">
                                        Départ
                                    </div>
                                    <input
                                        type="date"
                                        className="rounded-3xl border-1 border-gray-300 w-full h-10 px-4 mt-2"
                                        value={departureDate}
                                        onChange={(e) => setDepartureDate(e.target.value)}
                                        required />
                                </div>
                                <div className="mt-6">
                                    <div className="ml-2">
                                        Voyageurs
                                    </div>
                                    <input
                                        type="number"
                                        min={1}
                                        max={10}
                                        className="rounded-3xl border-1 border-gray-300 w-full h-10 px-4 mt-2"
                                        value={guestsCount}
                                        onChange={(e) => setGuestsCount(parseInt(e.target.value))}
                                        required />
                                </div>
                            </div>

                            <div className="mt-8 flex items-center gap-5">
                                <button type="submit" className="rounded-3xl bg-gray-200 text-gray-800 px-6 py-2 cursor-pointer">
                                    Réserver
                                </button>
                                <div className="text-gray-400 text-sm ml-1">Aucun montant ne vous sera débité pour le moment</div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>}
    </>
}
