import Head from 'next/head'
import Layout from '../../../components/layout'
import SxStatusPing from "../../../src/query/status/SxStatusPing";

export default function Status() {
    return (
        <Layout>
            <Head>
                <title>Service status</title>
            </Head>
            <h1>Service status</h1>
            <SxStatusPing/>
        </Layout>
    )
}