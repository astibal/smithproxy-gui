import Head from 'next/head'
import Layout from '../../../components/layout'
import SxProxyList from "../../../src/query/proxy/SxProxyList";

export default function Status() {
    return (
        <Layout>
            <Head>
                <title>Service status</title>
            </Head>
            <h1>Proxy list</h1>
            <SxProxyList/>
        </Layout>
    )
}